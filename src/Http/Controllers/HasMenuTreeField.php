<?php

namespace Dcat\Admin\Http\Controllers;

use Dcat\Admin\Form;

trait HasMenuTreeField
{
    /**
     * Add menu tree field to form.
     */
    protected function addMenuTreeField(Form $form)
    {
        $form->tree('menus', trans('admin.menu'))
            ->treeState(false)
            ->setTitleColumn('title')
            ->nodes(function () {
                $model = config('admin.database.menu_model');

                return (new $model())->allNodes();
            })
            ->customFormat(function ($v) {
                if (! $v) {
                    return [];
                }

                return array_column($v, 'id');
            });
    }

    /**
     * Flush menu cache after form saved.
     */
    protected function flushMenuCache()
    {
        $model = config('admin.database.menu_model');
        (new $model())->flushCache();
    }
}
