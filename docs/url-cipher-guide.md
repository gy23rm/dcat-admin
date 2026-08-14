# dcat-admin 路由主键加密功能使用说明

> 适用于 `zgy-dcat/laravel-admin`（dcat-admin）的路由主键加密能力。
> 页面 URL 中的主键（如 `/admin/books/1/edit` 里的 `1`）会被加密成不可读的密文（默认
> **36 位 UUID 样式**），防止直接暴露数据库主键。

---

## 1. 快速开始

### 1.1 启用加密

在项目根目录 `.env` 中配置：

```dotenv
# 是否启用 URL 主键加密
ADMIN_ROUTE_ENCRYPT=true

# 加解密盐（字符串，必须有值；改盐会让旧密文全部失效）
ADMIN_ROUTE_CIPHER_SALT=111
```

> **注意**：`ADMIN_ROUTE_CIPHER_SALT` 必填且不能为空，否则加解密会抛异常。
> 修改盐之前生成的密文将在修改后无法解密，请勿随意变更。

启用后 `php artisan config:clear` 刷新配置缓存。

### 1.2 验证是否生效

打开任意后台列表页（如 `/admin/books`），查看「编辑 / 查看 / 删除」按钮链接：

- 启用前：`/admin/books/1/edit`
- 启用后：`/admin/books/f5a24e32-xxxx-xxxx-xxxx-xxxxxxxxxxxx/edit`（UUID 样式密文）

登录与权限等原有功能不受影响，控制器里拿到的主键**仍是明文**（由中间件自动解密）。

---

## 2. 加密范围

启用后，以下场景的 URL 主键会被加密（`encrypt=true` 时才生效，默认 `false` 完全不影响现有功能）：

| 场景 | 组件 | 说明 |
|---|---|---|
| Grid 行操作 | 编辑 / 查看 / 删除按钮 | 自动生效 |
| Delete 弹窗 | 单行 / 批量删除确认弹窗 | 不再展示明文主键 |
| Form 表单 | 编辑页提交、查看、删除 | 自动生效 |
| Show 详情页 | 编辑 / 删除按钮 | 自动生效 |
| Tree 树形列表 | 编辑 / 快速编辑 / 删除 | 自动生效 |
| 行内编辑 | `editable()`、`select()`、`switch()`、`switchGroup()` | 自动生效 |
| 行内排序 | `orderable()` 的 ↑↓ 排序请求 | 启用后自动生效 |

**不加密**：

- Query 字符串参数（`?filter=xx` 等）不受影响
- **批量删除选中主键**（`data-id` / `keys`）为明文：批量删除按钮的请求 URL 是
  `resource/{id1,id2,...}`，其中 `keys` 来自 Grid 行选择器（RowSelector）的 `data-id`。
  该通道同时被「导出选中行」复用（`ExportButton` 直接拼 `__rows__`），
  因此保持明文以兼容导出；确认弹窗已置空，不展示这些明文主键。
- **单行删除**（Grid/Tree/Form 的删除按钮）是**加密的**：`data-url` 里的主键经
  `admin_cipher_encrypt($key, 'grid.id' / 'form.id')` 加密，只有确认弹窗文案被置空
  （不展示明文），URL 本身是密文。

---

## 3. 作用域（Scope）

加密时有一个「作用域」概念，用于区分同一个主键在不同上下文下的密文。

| 上下文 | 作用域 | 用途 |
|---|---|---|
| Grid 行操作 | `grid.id` | 列表页按钮 |
| Form 表单 | `form.id` | 表单页提交/删除 |
| 其它（内置调用点） | `grid.id` / `form.id` | 统一由内置代码处理 |

**控制器身份前缀（可选）**：控制器可定义 `cipherScope` 属性，加密时会把控制器身份前缀合成进作用域
（如 `book:grid.id`），进一步隔离不同控制器的密文，防止跨模块重放：

```php
class BookController extends AdminController
{
    // 指定该控制器 URL 加密的身份前缀
    protected $cipherScope = 'book';
}
```

> 不设置 `cipherScope` 时行为等同旧版，不叠加身份。**解密侧不需要关心作用域**——密文自带
> scope 标识，中间件自动还原，手动解密时只需传入加密时相同的 scope。

---

## 4. 手动加解密（公开 Helper）

包提供两个公开全局函数，`$key`（作用域）**必填**，主键**仅支持正整数**：

```php
// helpers.php 无 namespace，函数是全局的，直接调用即可
$cipher = admin_cipher_encrypt(42, 'book:grid.id');
```

### 4.1 加密

```php
$cipher = admin_cipher_encrypt(42, 'book:grid.id');
// 返回：f5a24e32-xxxx-xxxx-xxxx-xxxxxxxxxxxx（UUID 样式密文）
// 参数：$plain 正整数主键（int，弱类型下数字字符串也能传）；$key 作用域必填
```

- 非正整数（`0` / `负数` / 非数字）→ 抛 `InvalidArgumentException`
- 未传 `$key` / 空串 → 抛 `InvalidArgumentException`

### 4.2 解密

```php
$plain = admin_cipher_decrypt($cipher, 'book:grid.id');
// 返回：'42'（明文主键字符串）；失败返回 null
// 参数：$cipher 密文；$key 作用域必填，需与加密时一致
```

- 未传 `$key` / 空串 → 抛 `InvalidArgumentException`
- 传入的 `$key` 与密文内嵌 scope 不一致 → 返回 `null`
- 解密结果非正整数 → 返回 `null`

### 4.3 完整示例

```php
// 加密
$cipher = admin_cipher_encrypt($book->id, 'book:grid.id');   // 'f5a24e32-...'
$url    = "/admin/books/{$cipher}/edit";

// 解密
$id = admin_cipher_decrypt($cipher, 'book:grid.id');          // '42'
if ($id === null) {
    abort(404);
}
```

---

## 5. 配置项详解

`config/admin.php` 的 `route` 段：

```php
'route' => [
    // 是否启用 URL 主键加密（默认 false）
    'encrypt' => env('ADMIN_ROUTE_ENCRYPT', false),

    // 加解密实现类，必须实现 \Dcat\Admin\Contracts\UrlCipher
    // 当前默认：UuidCipher（AES 伪 UUID 版，密文 36 位 UUID 样式）
    // 可选：    CryptCipher（配置盐混淆版，密文 [scope]:hex）
    'cipher' => \Dcat\Admin\Support\UuidCipher::class,

    // 加解密盐（必须有值）
    'cipher_salt' => env('ADMIN_ROUTE_CIPHER_SALT', 'dcat_c'),
],
```

### 两种内置实现对比

| | **UuidCipher**（默认） | **CryptCipher**（可选） |
|---|---|---|
| 密文样式 | 36 位 UUID：`f5a24e32-xxxx-...` | `[grid.id]:a1b2c3...`（hex） |
| 密钥派生 | AES-256 + PBKDF2（100k 迭代） | 配置盐 XOR 混淆（sha256 派生） |
| 支持主键 | 非负 int | 非负 int（正整数） |
| 适用场景 | 追求密文形式隐蔽、更安全 | 简单轻量、可读性略高 |

切换实现只需改 `cipher` 配置（需要同时保证 `cipher_salt` 存在）：

```php
'cipher' => \Dcat\Admin\Support\CryptCipher::class,
```

> 切换后旧密文无法解密（加密算法不同），请合理安排切换时机。

---

## 6. 自定义加密实现

如果内置两种都不满足，可实现 `UrlCipher` 接口：

```php
<?php

namespace App\Support;

use Dcat\Admin\Contracts\UrlCipher;

class MyCipher implements UrlCipher
{
    public function encrypt(int $plain, ?string $key = null): string
    {
        // 返回 URL 安全字符集的密文
        return base64_encode("{$plain}|{$key}");
    }

    public function decrypt(string $cipher, ?string $key = null): ?string
    {
        $raw = base64_decode($cipher, true);
        [$plain, $scope] = explode('|', $raw);
        if ($key !== null && $key !== $scope) {
            return null;   // scope 不匹配拒绝
        }
        return $plain;
    }
}
```

然后在 `config/admin.php` 指定：

```php
'cipher' => \App\Support\MyCipher::class,
```

接口签名（`Contracts/UrlCipher.php`）：

```php
public function encrypt(int $plain, ?string $key = null): string;
public function decrypt(string $cipher, ?string $key = null): ?string;
```

---

## 7. 常见问题

### 7.1 页面 URL 还是明文？

确认 `.env` 里 `ADMIN_ROUTE_ENCRYPT=true` 且执行了 `php artisan config:clear`。
默认值是 `false`（`.env.example` 里也是 `false`），不改就完全不加密。

### 7.2 改了 salt 后所有链接打不开了？

对，改了 `ADMIN_ROUTE_CIPHER_SALT` 会让旧密文全部失效。中间件解密失败会回退明文尝试，
但基本都会 404。**salt 定下来就别改**，或者在无存量密文时再改。

### 7.3 控制器里拿到的还是明文吗？

是的。中间件负责把 URL 里的密文主键解密回明文，控制器 `$id` 收到的仍是正常的主键值，
业务代码无需改动。

### 7.4 Orderable 排序按钮没有加密？

`orderable()` 是可选 displayer，需要你在 Grid 里启用才有：

```php
$grid->column('sort')->orderable();
```

启用后 ↑↓ 图标的 `data-id` 和排序 PUT 请求 URL 会自动携带密文。

### 7.5 手动解密失败？

`admin_cipher_decrypt` 要求传入与加密时**完全一致的 scope**。加密用了 `book:grid.id`，
解密就必须传 `book:grid.id`（不是 `grid.id`），否则返回 null。

---

## 8. 文件清单（涉及本次功能）

```
src/Contracts/UrlCipher.php                 # 加解密接口契约
src/Support/UrlCipherManager.php            # 统一入口（encrypt/decrypt/开关判断）
src/Support/CryptCipher.php                 # 默认实现 B：配置盐混淆版
src/Support/UuidCipher.php                  # 默认实现 A：AES 伪 UUID 版
src/Http/Middleware/Cipher.php              # 中间件（解密路由主键）
src/Http/Controllers/AdminController.php    # cipherScope getter
src/Support/helpers.php                     # admin_cipher_encrypt / admin_cipher_decrypt
```

---

*文档版本：2026-08-14，对应 `UuidCipher` 默认实现。*