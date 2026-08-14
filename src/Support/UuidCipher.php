<?php

namespace Dcat\Admin\Support;

use Dcat\Admin\Contracts\UrlCipher;

/**
 * UUID 伪装版 URL 主键加解密实现.
 *
 * 把 int64 主键包装成「看起来像随机 UUID」的密文，输出 36 字符 UUID 格式。
 *
 * 字节布局（16 字节明文 = 一个 AES 块，无需填充）：
 *   ┌─────────────┬──────────────────────┬─────────────────┐
 *   │ md5 校验(4B) │ bigInt 大端 J(8B)     │ scope 指纹(4B)   │
 *   └─────────────┴──────────────────────┴─────────────────┘
 *   ① 作用域指纹 = md5(scope) 前 4 字节（替代原时间戳字段）；
 *   ② 对 [bigInt(8)+scope(4)] 12 字节求 md5，取前 4 字节作为完整性校验；
 *   ③ 16 字节整体走 AES-256-ECB 加密（OPENSSL_ZERO_PADDING，数据恰好一块）；
 *   ④ bin2hex 后按 8-4-4-4-12 拼成标准 UUID 字符串。
 *
 * 解密为逆过程：AES 解密 → 校验 md5 → 还原 bigInt。
 * 校验失败 / 格式非法 → 返回 null（由调用方决定是否回退明文）；
 * 显式传入 scope（key）时还会校验与密文中内嵌的指纹一致，不一致返回 null。
 *
 * 作用域语义：同一明文在不同 scope（grid.id / form.id）下产出不同密文，
 * 防止跨场景重放；且加密结果确定（同 scope 同明文的密文幂等），URL 稳定可收藏。
 *
 * 密钥派生（PBKDF2 + 缓存）：
 * - AES-256 密钥 = PBKDF2-HMAC-SHA256(cipher_salt, domain 盐, 100000 迭代, 32 字节)；
 * - 强 KDF 拉伸低熵配置盐，离线暴力破解成本显著上升；
 * - 密钥在首次使用时派生并缓存（实例是 singleton，渲染 Grid 时不会反复计算）。
 *
 * 注意事项：
 * - 仅支持非负 int 主键（pack('J') 对负数行为有歧义，自增主键本就非负）；
 * - 输出的「UUID」只是密文形式，不是 RFC4122 合法 UUID（版本/变体位是密文随机比特），
 *   不要作为真实 UUID 传给需要严格校验 UUID 的第三方系统；
 * - AES-ECB 确定性：同一明文（同 scope）产出同一密文，可据此观察「哪些 URL 指向同一条
 *   记录」；对「隐藏主键 + 防枚举」足够，不是机密性/防重放方案；
 * - 默认中间件不传 scope：解密时不校验指纹，仅还原主键；
 *   需要强校验的场景可在调用方（如控制器）显式传入 scope；
 * - 切换 cipher_salt 后旧链接无法解密（属预期）。
 *
 * 默认仍为 {@see CryptCipher}；需要 UUID 伪装时把配置 admin.route.cipher
 * 改为本类即可。
 */
class UuidCipher implements UrlCipher
{
    /**
     * PBKDF2 迭代次数：每次请求仅首次派生，之后走缓存，成本可控.
     */
    protected const PBKDF2_ITERATIONS = 100000;

    /**
     * PBKDF2 域分隔盐，避免与其它用途的派生撞车.
     */
    protected const PBKDF2_SALT = 'dcat-admin.url-cipher.v1';

    /**
     * @var string|null 派生的 AES-256 密钥（32 字节），首次使用时缓存
     */
    protected ?string $secretKey = null;

    /**
     * {@inheritdoc}
     *
     * @throws \InvalidArgumentException 负数主键不支持
     * @throws \RuntimeException         cipher_salt 未配置或 AES 加密失败
     */
    public function encrypt(int $plain, ?string $key = null): string
    {
        if ($plain < 0) {
            throw new \InvalidArgumentException('UuidCipher 仅支持非负 int 主键，传入了：'.$plain);
        }

        // 作用域指纹（4 字节）：同一明文在不同 scope 下产出不同密文，防止跨场景重放
        $scope = substr(md5((string) $key, true), 0, 4);
        $payload = pack('J', $plain).$scope;

        // 1. 完整性校验：对 payload 12 字节求 md5，取前 4 字节
        $hash = substr(md5($payload, true), 0, 4);
        $plaintext = $hash.$payload; // 16 字节 = 一个 AES 块

        // 2. AES-256-ECB 加密（数据恰好 16 字节，零填充无副作用）
        $cipherRaw = openssl_encrypt($plaintext, 'aes-256-ecb', $this->secret(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        if ($cipherRaw === false) {
            throw new \RuntimeException('UuidCipher AES 加密失败，请检查 admin.route.cipher_salt 配置');
        }

        // 3. 32 位 hex 按 8-4-4-4-12 拼成 UUID 字符串
        $hex = bin2hex($cipherRaw);

        return implode('-', [
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20),
        ]);
    }

    /**
     * {@inheritdoc}
     *
     * - 长度非法 / 非 32 hex / 无连字符结构 → 视为非密文，返回 null（明文不误伤）；
     * - AES 解密失败或 md5 校验失败 → 返回 null（篡改拒绝）；
     * - 显式传入 scope（key）且与密文中内嵌指纹不一致 → 返回 null；
     * - 成功返回明文主键字符串。
     */
    public function decrypt(string $cipher, ?string $key = null): ?string
    {
        // 36 字符是合法 UUID 密文的最大长度，超长值直接视为非密文
        if (strlen($cipher) > 36) {
            return null;
        }

        $hex = str_replace('-', '', $cipher);

        if ($hex === '' || strlen($hex) !== 32 || ! ctype_xdigit($hex)) {
            return null;
        }

        $cipherRaw = hex2bin($hex);

        if ($cipherRaw === false || strlen($cipherRaw) !== 16) {
            return null;
        }

        $decrypted = openssl_decrypt($cipherRaw, 'aes-256-ecb', $this->secret(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        if ($decrypted === false || strlen($decrypted) !== 16) {
            return null;
        }

        // 校验 md5：前 4 字节 == 对剩余 12 字节求 md5 的前 4 字节
        $hash = substr($decrypted, 0, 4);
        $payload = substr($decrypted, 4);

        if ($hash !== substr(md5($payload, true), 0, 4)) {
            return null;
        }

        // 作用域校验：显式传入 scope 时，必须与密文中内嵌指纹一致
        if ($key !== null && substr(md5((string) $key, true), 0, 4) !== substr($payload, 8, 4)) {
            return null;
        }

        $bigInt = unpack('J', substr($payload, 0, 8));

        return (string) $bigInt[1];
    }

    /**
     * 从配置派生 AES-256 密钥并缓存（PBKDF2-HMAC-SHA256）；盐为空抛异常.
     *
     * @return string 32 字节密钥
     *
     * @throws \RuntimeException
     */
    protected function secret(): string
    {
        if ($this->secretKey !== null) {
            return $this->secretKey;
        }

        $salt = (string) config('admin.route.cipher_salt', '');

        if ($salt === '') {
            throw new \RuntimeException('admin.route.cipher_salt 未配置或为空，请设置 cipher_salt（如 ADMIN_ROUTE_CIPHER_SALT=xxx）');
        }

        $this->secretKey = hash_pbkdf2('sha256', $salt, static::PBKDF2_SALT, static::PBKDF2_ITERATIONS, 32, true);

        return $this->secretKey;
    }
}