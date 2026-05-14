<?php
/**
 * @file    auth_http_cookie.php
 *
 * User and Session Handling Library
 *
 * This file contains classes for session
 * handling.
 *
 *
 * copyright (c) 2010 Frank Hellenkamp [jonas@depage.net]
 * copyright (c) 2010 Lion Vollnhals
 *
 * @author    Lion Vollnhals
 * @author    Frank Hellenkamp [jonas@depage.net]
 */

namespace Depage\Auth\Methods;

use Depage\Auth\Auth;
use Depage\Auth\User;
use Depage\Html\Html;

class HttpCookie extends Auth
{
    // {{{ variables
    protected $cookiePath = "";
    /**
     * @brief name of the session cookie
     **/
    public $cookieName = "depage-session-id";
    /**
     * @brief domain of the cookie
     *
     * false is the php default to use current domain automatically
     **/
    public $cookieDomain = false;
    /**
     * @brief set cookie only through secure connection
     **/
    public $cookieSecure = true;
    /**
     * @brief set http-only cookie -> no javascript access
     **/
    public $cookieHttponly = true;

    public $cookieSameSite = 'None';

    public $includeSubdomains = false;
    // }}}

    /* {{{ constructor */
    public function __construct($pdo, $realm, $domain, $digestCompat = false) {
        parent::__construct($pdo, $realm, $domain, $digestCompat);

        // increase lifetime of cookies in order to allow detection of timedout users
        $url = parse_url($domain);
        $this->cookiePath = !empty($url['path']) ? $url['path'] : '';
        $this->cookieName = \Depage\Auth\Auth::getSessionName($this->realm, $this->domain);
        $this->cookieDomain = $url['host'];

        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != "off") {
            $this->cookieSecure = true;
        } elseif (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? "") == "https") {
            $this->cookieSecure = true;
        } else {
            $this->cookieSecure = false;
        }
        session_set_cookie_params([
            'lifetime' => $this->sessionLifetime,
            'path' => $this->cookiePath,
            'domain' => "." . $this->cookieDomain,
            'secure' => $this->cookieSecure,
            'httponly' => $this->cookieHttponly,
            'samesite' => $this->cookieSameSite,
        ]);
        session_name($this->cookieName);
    }
    /* }}} */

    /* {{{ enforce */
    public function enforce($testUserFunction = null) {
        // only enforce authentication if not authenticated before
        if (!$this->user) {
            $this->user = $this->authCookie();
        }

        // test user with custom user function
        if ($this->user && !is_null($testUserFunction)) {
            $this->user = $testUserFunction($this->user);
        }

        // redirect to login page
        if (!$this->user) {
            // remove trailing slashes when comparing urls, disregard query string
            $loginUrl = Html::link($this->loginUrl, "auto");

            // set protocol
            if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != "off") {
                $protocol = "https://";
            } elseif (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? "") == "https") {
                $protocol = "https://";
            } else {
                $protocol = "http://";
            }

            $requestUrl = strstr($protocol . $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"] . '?', '?', true);
            if (rtrim($loginUrl, '/') != rtrim($requestUrl, '/')) {
                $redirectTo = urlencode($_SERVER['REQUEST_URI']);

                \Depage\Router\Router::redirect("$loginUrl?redirectTo=$redirectTo");
            }
        }

        return $this->user;
    }
    /* }}} */
    /* {{{ enforceLazy*/
    /**
     * @return   function returns the authenticated user or false if not logged in
     */
    public function enforceLazy() {
        if (!$this->user) {
            if ($this->hasSession()) {
                if (isset($_COOKIE[$this->cookieName]) && $this->isValidSid($_COOKIE[$this->cookieName])) {
                    $this->user = $this->authCookie();
                } else {
                    $this->justLoggedOut = true;
                    $this->user = false;
                }
            } else {
                $this->user = false;
            }
        }

        return $this->user;
    }
    /* }}} */
    /* {{{ enforceLogout */
    public function enforceLogout() {
        if ($this->hasSession()) {
            $this->justLoggedOut = true;
            $this->logout($_COOKIE[$this->cookieName]);
            $this->destroySession();
        }
    }
    /* }}} */
    /* {{{ check() */
    public function check($username, $password) {
        try {
            if (strpos($username, "@") !== false) {
                // email login
                $user = User::loadByEmail($this->pdo, $username);
            } else {
                // username login
                $user = User::loadByUsername($this->pdo, $username);
            }

            if ($user->disabled) {
                return false;
            }

            $pass = new \Depage\Auth\Password($this->realm, $this->digestCompat);

            if ($pass->verify($user->name, $password, $user->passwordhash)) {
                $this->updatePasswordHash($user, $password);

                if (defined("DEPAGE_LANG")) {
                    $user->lang = DEPAGE_LANG;
                    $user->save();
                }

                return $user;
            } else {
                $this->prolongLogin($user);
            }
        } catch (\Depage\Auth\Exceptions\User $e) {
        }

        return false;
    }
    /* }}} */
    /* {{{ login() */
    public function login($username, $password) {
        $user = $this->check($username, $password);

        if ($user) {
            $this->destroySession();
            $this->registerSession($user->id);
            $sid = $this->startSession();

            $user->onLogin($sid);

            $this->user = $user;

            return $this->user;
        }

        return false;
    }
    /* }}} */

    /* {{{ authCookie() */
    protected function authCookie() {
        if ($this->hasSession()) {
            if ($this->isValidSid($_COOKIE[$this->cookieName]) !== false) {
                $this->setSid($_COOKIE[$this->cookieName]);
                $this->startSession();

                $user = User::loadBySid($this->pdo, $this->getSid());

                if ($user && $user->disabled) {
                    return false;
                }

                return $user;
            } else {
                $this->justLoggedOut = true;
                if (!empty($this->log)) {
                    $this->log->log("http_auth_cookie: invalid session ID");
                }
            }
        }

        $this->sendAuthHeader();

        //throw new Exception("you are not allowed to do this!");
        return false;
    }
    /* }}} */

    // {{{ startSession()
    protected function startSession() {
        $sid = $this->getSid();

        if ($this->includeSubdomains) {
            $this->cookieDomain = "." . $this->cookieDomain;
        }

        if (!is_callable("session_status") || session_status() !== \PHP_SESSION_ACTIVE) {
            session_id($sid);
            session_start();
        }

        return $sid;
    }
    // }}}
    // {{{ hasSession()
    protected function hasSession() {
        if (is_callable("session_status") && session_status() == \PHP_SESSION_ACTIVE) {
            // PHP 5.4
            return true;
        } else {
            // PHP 5.3
            return isset($_COOKIE[$this->cookieName]) && $_COOKIE[$this->cookieName] != "";
        }
    }
    // }}}
    // {{{ destroySession()
    protected function destroySession() {
        if (!is_callable("session_status") || session_status() == \PHP_SESSION_ACTIVE) {
            // delete cookie
            setcookie(
                $this->cookieName,
                $this->getSid(),
                [
                    'expires' => time() - 42000,
                    'path' => $this->cookiePath,
                    'domain' => $this->cookieDomain,
                    'secure' => $this->cookieSecure,
                    'httponly' => $this->cookieHttponly,
                    'samesite' => $this->cookieSameSite,
                ]
            );
            unset($_COOKIE[$this->cookieName]);
            session_destroy();
        }
    }
    // }}}

    // {{{ sendAuthHeader()
    protected function sendAuthHeader($validResponse = false) {
        // @todo look for a way to suppress password saving dialogs when password is wrong
        //header("HTTP/1.1 403 Unauthorized");
    }
    // }}}
}

/* vim:set ft=php sw=4 sts=4 fdm=marker : */
