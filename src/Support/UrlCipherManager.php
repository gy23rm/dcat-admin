<?php

namespace Dcat\Admin\Support;

use Dcat\Admin\Contracts\UrlCipher;

/**
 * URL 主键加解密管理器.
 *
 * - 作为包内统一入口：Grid/Form 的主键加密、中间件解密都通过它干活；
 * - 仅面向「主键」场景：加密路径参数中的记录 ID（grid.id / form.id），
 *   其它查询参数一律保持明文，不做打包 / 分组。
 *
 * 作用域（scope）设计（方案 C：控制器前缀合成）：
 * - 内置调用点仍传显式 scope（grid.id / form.id），无需改动；
 * - encrypt 时，若当前控制器显式配置了 cipherScope，会把「该属性值」与传入 scope
 *   合成为复合 scope：{cipherScope}:{scope}（如 book:grid.id），
 *   从而让不同资源下的同 id 密文天然隔离；
 * - 身份仅取自 $controller->cipherScope（显式配置）；无该属性时不叠加身份，
 *   保持原 scope 不变（旧行为）；不用 title / 类名兜底；
 * - 显式启停：config('admin.route.encrypt') 为 false 时整个链路不加密。
 *
 * 用法：
 *   $manager = app('admin.cipher');
 *   $enc = $manager->encrypt(42, 'grid.id');         // BookController 下 → book:grid.id
 *   $enc = $manager->encrypt(42);                    // 无控制器 → 原样（null）
 *   $dec = $manager->decrypt($enc);                  // 不传 scope 自动还原
 */
class UrlCipherManager
{
    /**
     * @var UrlCipher
     */
    protected $cipher;

    public function __construct(UrlCipher $cipher)
    {
        $this->cipher = $cipher;
    }

    /**
     * 加密主键值（仅支持 int；scope 可空）.
     *
     * 若当前请求可解析出控制器身份，会把身份前缀合成进 scope，
     * 形成 {身份}:{scope}（如 book:grid.id）。
     *
     * @param  int  $plain
     * @param  string|null  $key  作用域标识（如 grid.id / form.id），可空
     * @return string
     */
    public function encrypt(int $plain, ?string $key = null): string
    {
        $identity = $this->resolveDefaultScope();

        // 身份合成：只有拿到控制器身份时才加前缀；否则原样（含 null）
        if ($identity !== null) {
            $key = $key === null || $key === ''
                ? $identity
                : $identity.':'.$key;
        }

        return $this->cipher->encrypt($plain, $key);
    }

    /**
     * 解密主键值；失败返回 null.
     *
     * 密文内嵌 scope 指纹，不传 $key 时由实现自动识别，无需控制器上下文。
     *
     * @param  string  $cipher
     * @param  string|null  $key  作用域标识，需与加密时一致；不传时自动识别
     * @return string|null
     */
    public function decrypt(string $cipher, ?string $key = null): ?string
    {
        return $this->cipher->decrypt($cipher, $key);
    }

    /**
     * 是否启用主键加密（配置开关）.
     *
     * @return bool
     */
    public function enabled(): bool
    {
        return (bool) config('admin.route.encrypt', false);
    }

    /**
     * 控制器身份解析：
     *   仅使用 $controller->cipherScope（显式配置），无则返回 null（不叠加身份）；
     *   title / 类名均不做兜底.
     * 属性为 protected 时通过公开 getter / 反射读取；
     * 空串属性视为未配置；任一环节失败 / 无控制器返回 null（不抛异常）.
     *
     * @return string|null
     */
    protected function resolveDefaultScope(): ?string
    {
        $controller = $this->currentController();

        if (! $controller) {
            return null;
        }

        // 仅使用显式配置的 cipherScope（优先公开 getter，其次反射读 protected）
        $scope = $this->readControllerProperty($controller, 'cipherScope');

        if ($scope !== null && $scope !== '') {
            return (string) $scope;
        }

        return null;
    }

    /**
     * 安全读取控制器属性（兼容 protected/private）：
     * - 优先调用公开 getter（如 cipherScope()）；
     * - 无 getter 时用反射读取（不抛异常，读不到返回 null）.
     *
     * @param  object  $controller
     * @param  string  $property
     * @return mixed
     */
    protected function readControllerProperty($controller, string $property)
    {
        if (method_exists($controller, $property)) {
            try {
                $value = $controller->{$property}();

                return $value;
            } catch (\Throwable $e) {
                // 方法抛异常则继续尝试反射
            }
        }

        if (! property_exists($controller, $property)) {
            return null;
        }

        try {
            $ref = new \ReflectionProperty($controller, $property);
            $ref->setAccessible(true);

            return $ref->getValue($controller);
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * 获取当前请求路由绑定的控制器实例；拿不到返回 null.
     *
     * @return object|null
     */
    protected function currentController(): ?object
    {
        if (! function_exists('request')) {
            return null;
        }

        $route = request()->route();

        if (! $route) {
            return null;
        }

        // getController() 可能抛异常（路由尚未绑定 controller / 闭包路由），
        // 一律按"无控制器"处理，绝不把异常抛给调用方
        try {
            return $route->getController();
        } catch (\Throwable $e) {
            return null;
        }
    }
}