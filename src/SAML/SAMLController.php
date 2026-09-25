<?php

namespace SocialiteProviders\SAML;

use Aacotroneo\Saml2\Http\Controllers\Saml2Controller;

class SAMLController extends Saml2Controller
{

    public static function getCertificateContent($setting)
    {
        if (empty(config('services.saml.' . $setting))) {
            return null;
        }
        return file_get_contents(storage_path('app/private/settings/') .'services.saml.' . $setting);
    }

    public static function stripCertificateDelimiters($cert)
    {
        if (empty($cert)) {
            return null;
        }
        $result = $cert;
        $result = str_replace('-----BEGIN CERTIFICATE-----', "", $result);
        $result = str_replace('-----END CERTIFICATE-----', "", $result);
        $result = str_replace(' ', '', $result);
        return $result;
    }

}
