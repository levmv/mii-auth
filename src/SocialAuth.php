<?php declare(strict_types=1);

namespace mii\auth;

use Hybridauth\Adapter\AdapterInterface;
use mii\db\DB;
use mii\log\Log;
use mii\util\URL;

class SocialAuth extends Auth
{
    public const FACEBOOK = 'fb';
    public const VK = 'vk';
    public const ODNOKLASSNIKI = 'ok';
    public const YANDEX = 'ya';
    public const INSTAGRAM = 'ig';

    protected bool $join_accounts = true;

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
        self::FACEBOOK => 'Hybridauth\\Provider\\Facebook',
        self::VK => 'Hybridauth\\Provider\\Vkontakte',
        self::YANDEX => 'Hybridauth\\Provider\\Yandex',
        self::ODNOKLASSNIKI => 'Hybridauth\\Provider\\Odnoklassniki',
    ];

    public function socialAuth(string $provider) : bool
    {
        $provider_name = $this->providers_classes[$provider];

        $config = [
            'callback'  => URL::base(true).URL::current(),
            'keys' => $this->providers[$provider],
        ];

        /**
         * @var $adapter AdapterInterface
         */
        $adapter = new $provider_name($config, null, new SocialStorage());

        DB::begin();
        try {
            if (!$adapter->isConnected()) {
                $adapter->authenticate();
            }

            $profile = $adapter->getUserProfile();

            // Convert HybridAuthProfile to our SocialProfile
            $profile = new SocialProfile($profile);

            $social = UserSocial::where([
                ['identity', '=', $profile->identifier],
                ['network', '=', $provider],
            ])->one();

            $userModel = $this->getUserModel();

            if ($social !== null) {
                $user = $userModel::oneOrFail($social->user_id);
                return $this->loginSocialUser($user);
            }

            $user = null;

            if ($this->join_accounts && $profile->email) {
                $user = $userModel::findUser($profile->email);
            }

            if (!$user) {
                $user = $userModel::createUserFromSocial($profile);
            }

            $social = new UserSocial([
                'network' => $provider,
                'user_id' => $user->id,
                'identity' => $profile->identifier,
            ]);
            $social->create();

            return $this->loginSocialUser($user);
        } catch (\Throwable $t) {
            Log::error($t);
            DB::rollback();
        } finally {
            DB::commit();
            $adapter->disconnect();
        }
        return false;
    }

    private function loginSocialUser(User $user): bool
    {
        if (!$user->canLogin()) {
            return false;
        }

        $this->forceLogin($user);

        return true;
    }
}
