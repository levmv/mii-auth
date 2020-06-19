<?php declare(strict_types=1);

namespace mii\auth;

use mii\log\Log;
use mii\util\URL;

class SocialAuth extends Auth {

    public const FACEBOOK = 'fb';
    public const VK = 'vk';
    public const ODNOKLASSNIKI = 'ok';
    public const INSTAGRAM = 'inst';

    /**
     * @var array of providers configuration, like:
     * [
     *    self::FACEBOOK => [
     *       'id' => '...',
     *       'secret' => '...'
     *    ],
     * ]
     */
    protected array $providers = [];

    protected array $providers_classes = [
        self::FACEBOOK => 'Hybridauth\\Provider\\Facebook'
    ];


    public function socialAuth(string $provider) : bool
    {
        $provider_name = $this->providers_classes[$provider];

        $config = [
            'callback'  => URL::current(),
            'keys' => $this->providers[$provider]
        ];

        $adapter = new $provider_name($config, null, new SocialStorage());

        if (!$adapter->isConnected()) {
            $adapter->authenticate();
        }

        $profile = $adapter->getUserProfile();

        $social = UserSocial::where([
            ['identity', '=', $profile->identifier],
            ['network', '=', $provider],
        ])->one();

        if ($social !== null) {
            $user = $this->getUserModel()::oneOrFail($social->user_id);
            return $this->login_user($user, $social);
        }

        if ($profile->email && $user = $this->getUserModel()->findUser($profile->email)) {

        }

        // В ином случае поищем пользователя по email
        $user = $this->find_existed_user($profile, $adapter);

        // Если не найден, то создадим нового пользователя
        if (!$user) {
            $user = $this->create_user($profile, $provider);
        }
        // Создадим новую привязку к аккаунту в соц.сети
        $social = new UserSocial([
            'network' => $provider,
            'user_id' => $user->id,
            'identity' => $profile->identifier,
        ]);
        $social->create();

        Log::info('new social autorize', $social);

        return $this->login_user($user, $social);

    }

    private function loginSocialUser(User $user, UserSocial $social): bool
    {
        if (!$user->canLogin()) {
            return false;
        }

        $this->forceLogin($user);

        return true;
    }

    private function findExistedUser(Profile $profile): ?User
    {
        if ($profile->email) {
            return User::where(['username' => mb_strtolower($profile->email)])->one();
        }
        return null;
    }
}
