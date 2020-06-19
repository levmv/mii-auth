<?php declare(strict_types=1);

namespace mii\auth;


class SocialProfile {

    /**
     * The Unique user's ID on the connected provider
     *
     * @var integer
     */
    public $identifier = null;


    /**
     * URL link to user photo or avatar
     *
     * @var string
     */
    public $photoURL = null;


    /**
     * User's first name
     *
     * @var string
     */
    public $firstName = null;

    /**
     * User's last name
     *
     * @var string
     */
    public $lastName = null;

    /**
     * male or female
     *
     * @var string
     */
    public $gender = null;

    /**
     * Language
     *
     * @var string
     */
    public $language = null;

    /**
     * User age, we don't calculate it. we return it as is if the IDp provide it.
     *
     * @var integer
     */
    public $age = null;

    /**
     * User email. Note: not all of IDp grant access to the user email
     *
     * @var string
     */
    public $email = null;

    /**
     * Verified user email. Note: not all of IDp grant access to verified user email
     *
     * @var string
     */
    public $emailVerified = null;

    /**
     * Phone number
     *
     * @var string
     */
    public $phone = null;

}
