<?php

namespace Dcat\Admin\Http\Middleware;

use Dcat\Admin\Support\UrlCipherManager;
use Illuminate\Http\Request;

/**
 * URL 主键解密中间件.
 *
 * 放在 admin 中间件组最前端，负责解密路由路径参数中的主键
 * （如 /users/{id}/edit 中的 {id}），覆盖 route parameters。
 *
 * 仅加密主键，其它查询参数（过滤条件等）保持明文，不做处理。
 */
class Cipher
{
    /**
     * @var UrlCipherManager
     */
    protected $manager;

    public function __construct(UrlCipherManager $manager)
    {
        $this->manager = $manager;
    }

    public function handle(Request $request, \Closure $next)
    {
        if (! $this->manager->enabled()) {
            return $next($request);
        }

        $this->decryptRouteParameters($request);

        return $next($request);
    }

    /**
     * 解密路由路径参数（仅尝试，失败回退明文）.
     *
     * @return void
     */
    protected function decryptRouteParameters(Request $request)
    {
        $route = $request->route();

        if (! $route) {
            return;
        }

        $parameters = $route->parameters();

        foreach ($parameters as $key => $value) {
            if (! is_string($value) || $value === '') {
                continue;
            }

            // 路径参数由 Grid/Form 以短标签作用域（gi / fo / bo 等）加密，
            // 这里不指定 scope，由实现自动剥离作用域前缀还原明文
            $plain = $this->manager->decrypt($value);

            if ($plain !== null) {
                $route->setParameter($key, $plain);
            }
        }
    }
}