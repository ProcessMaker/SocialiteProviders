<?php

namespace SocialiteProviders\LDAP;

use SocialiteProviders\Manager\SocialiteWasCalled;

class LDAPExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param  \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('ldap', Provider::class);
    }
}
