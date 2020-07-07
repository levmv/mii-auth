<?php declare(strict_types=1);

namespace mii\auth;

use mii\core\ACL;
use mii\web\ForbiddenHttpException;

trait CheckAccess
{
    abstract protected function accessRules(): ACL;

    protected function onAccessDenied(): void
    {
        throw new ForbiddenHttpException('User has no rights to access ' . $this->request->uri());
    }

    public function execute(string $action, $params): void
    {
        $acl = $this->accessRules();

        $roles = \Mii::$app->auth->getUser() ? \Mii::$app->auth->getUser()->getRoles() : '*';

        if (empty($roles)) {
            $roles = '*';
        }

        if (!$acl->check($roles, $action)) {
            $this->onAccessDenied();
            return;
        }

        parent::execute($action, $params);
    }
}
