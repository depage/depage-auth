<?php
/**
 * @file    auth_user.php
 *
 *
 * copyright (c) 2002-2010 Frank Hellenkamp [jonas@depage.net]
 *
 * @author    Frank Hellenkamp [jonas@depage.net]
 */

namespace Depage\Auth;

/**
 * contains functions for handling user authentication
 * and session handling.
 */
class User extends \Depage\Entity\PdoEntity
{
    // {{{ variables
    /**
     * @brief fields
     **/
    static protected $fields = array(
        "type" => __CLASS__,
        "id" => null,
        "name" => "",
        "fullname" => "",
        "sortname" => "",
        "passwordhash" => "",
        "email" => "",
        "settings" => "",
        "dateRegistered" => null,
        "dateLastlogin" => null,
        "dateUpdated" => null,
        "dateResetPassword" => null,
        "confirmId" => null,
        "resetPasswordId" => null,
        "loginTimeout" => 0,
    );

    /**
     * @brief primary
     **/
    static protected $primary = array("id");

    /**
     * @brief pdo object for database access
     **/
    protected $pdo = null;

    /**
     * @brief useragent
     **/
     protected $useragent = "";

    /**
     * @brief string sid of user when load from loadActive()
     **/
    public $sid = null;
    // }}}

    // {{{ constructor()
    /**
     * constructor
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     *
     * @return      void
     */
    public function __construct(\Depage\Db\Pdo $pdo) {
        parent::__construct($pdo);

        $this->pdo = $pdo;

        // set class to called class (for subclasses of Depage\Auth\User)
        $this->data["type"] = get_class($this);
    }
    // }}}

    // {{{ loadByUsername()
    /**
     * gets a user-object by username directly from database
     *
     * @public
     *
     * @param       \Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       string  $username   username of the user
     *
     * @return      User
     */
    static public function loadByUsername($pdo, $username) {
        $user = current(self::loadBy($pdo, [
            'name' => $username,
        ]));

        if (!$user) {
            throw new Exceptions\User("user '$username' does not exist.");
        }

        return $user;
    }
    // }}}
    // {{{ loadByEmail()
    /**
     * gets a user-object by username directly from database
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       string  $email      email of the user
     *
     * @return      User
     */
    static public function loadByEmail($pdo, $email) {
        $user = current(self::loadBy($pdo, [
            'email' => $email,
        ]));

        if (!$user) {
            throw new Exceptions\User("user with email '$email' does not exist.");
        }

        return $user;
    }
    // }}}
    // {{{ loadBySid()
    /**
     * gets a user-object by sid (session-id) directly from database
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       string  $sid        session id
     *
     * @return      auth_user
     */
    static public function loadBySid($pdo, $sid) {
        $user = current(self::loadBy($pdo, [
            'sid' => $sid,
        ]));

        return $user;
    }
    // }}}
    // {{{ loadById()
    /**
     * gets a user-object by id directly from database
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       int     $id         id of the user
     *
     * @return      auth_user
     */
    static public function loadById($pdo, $id) {
        $user = current(self::loadBy($pdo, [
            'id' => $id,
        ]));

        if (!$user) {
            throw new Exceptions\User("user with id '$id' does not exist.");
        }

        return $user;
    }
    // }}}
    // {{{ loadByConfirmId()
    /**
     * gets a user-object by id directly from database
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       int     $id         id of the user
     *
     * @return      auth_user
     */
    static public function loadByConfirmId($pdo, $confirmId) {
        $user = current(self::loadBy($pdo, [
            'confirmId' => $confirmId,
        ]));

        return $user;
    }
    // }}}
    // {{{ loadByResetPasswordId()
    /**
     * gets a user-object by id directly from database
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       int     $id         id of the user
     *
     * @return      auth_user
     */
    static public function loadByResetPasswordId($pdo, $resetPasswordId) {
        $user = current(self::loadBy($pdo, [
            'resetPasswordId' => $resetPasswordId,
        ]));

        return $user;
    }
    // }}}
    // {{{ loadActive()
    /**
     * gets an array of user-objects
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       int     $id         id of the user
     *
     * @return      auth_user
     */
    static public function loadActive($pdo) {
        $users = self::loadBy($pdo, [
            'active' => true,
        ], [
            "user.sortname"
        ]);

        return $users;
    }
    // }}}
    // {{{ loadAll()
    /**
     * gets an array of user-objects
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       int     $id         id of the user
     *
     * @return      auth_user
     */
    static public function loadAll($pdo) {
        $users = self::loadBy($pdo, [], [
            "user.sortname"
        ]);

        return $users;
    }
    // }}}

    // {{{ loadBy()
    /**
     * @brief loadBy
     *
     * @param mixed $param
     * @return void
     **/
    static public function loadBy($pdo, Array $search, Array $order = [])
    {
        $users = [];
        $fields = "user." . implode(", user.", self::getFields());
        $where = [];
        $params = [];
        $groupBy = "";
        $orderBy = "";
        $join = [];

        // {{{ extract where part of query
        if (isset($search['id'])) {
            $where[] = self::sqlConditionFor('user.id', $search['id'], $params);
        }
        if (isset($search['name'])) {
            $where[] = self::sqlConditionFor('user.name', $search['name'], $params);
        }
        if (isset($search['email'])) {
            $where[] = self::sqlConditionFor('user.email', $search['email'], $params);
        }
        if (isset($search['confirmId'])) {
            $where[] = self::sqlConditionFor('user.confirmId', $search['confirmId'], $params);
        }
        if (isset($search['resetPasswordId'])) {
            $where[] = self::sqlConditionFor('user.resetPasswordId', $search['resetPasswordId'], $params);
        }
        if (isset($search['sid']) || (isset($search['active']) && $search['active'] == true)) {
            $fields .= ", session.sid";
            $join[] = "JOIN {$pdo->prefix}_auth_sessions AS session ON session.userid = user.id";
        }
        if (isset($search['sid'])) {
            $where[] = self::sqlConditionFor('session.sid', $search['sid'], $params);
        }
        if (isset($search['active']) && $search['active'] == true) {
            $fields .= ", session.ip, session.project, session.dateLastUpdate, session.useragent";
            $where[] = "session.dateLastUpdate > DATE_SUB(NOW(), INTERVAL 3 MINUTE)";
        }
        // }}}

        if (!empty($where)) {
            $where = "WHERE " . implode($where, " AND ");
        } else {
            $where = "";
        };

        // extract order part of query
        if (!empty($order)) {
            $orderBy = "ORDER BY " . implode(", ", $order);
        }
        $join = implode(" ", $join);

        $sql =
            "SELECT $fields
            FROM
                {$pdo->prefix}_auth_user AS user
                $join
            $where
            $groupBy
            $orderBy";

        $query = $pdo->prepare($sql);
        $query->execute($params);

        // pass pdo-instance to constructor
        $query->setFetchMode(\PDO::FETCH_CLASS, "Depage\\Auth\\User", [$pdo]);

        do {
            $user = $query->fetch(\PDO::FETCH_CLASS | \PDO::FETCH_CLASSTYPE);
            if ($user) {
                $user->onLoad();
                $users[$user->id] = $user;
            }
        } while ($user);

        return $users;
    }
    // }}}

    // {{{ setFullname()
    /**
     * @brief setFullname
     *
     * @param mixed $value
     * @return void
     **/
    protected function setFullname($value)
    {
        $this->data['fullname'] = $value;
        $this->dirty['fullname'] = true;

        $nameparts = explode(" ", trim($value));
        $this->data['sortname'] = end($nameparts);
        $this->dirty['sortname'] = true;

        return $this;
    }
    // }}}
    // {{{ setSortname()
    /**
     * @brief setSortname
     *
     * @param mixed $value
     * @return void
     **/
    protected function setSortname($value)
    {

    }
    // }}}
    // {{{ setPassword()
    /**
     * @brief setPassword
     *
     * @param mixed $
     * @return void
     **/
    public function setPassword($newPassword, $authDomain = "")
    {
        $pass = new \Depage\Auth\Password($authDomain);
        $this->passwordhash = $pass->hash($this->name, $newPassword);

        return $this;
    }
    // }}}
    // {{{ setSettings()
    /**
     * @brief setSettings
     *
     * @param mixed $param
     * @return void
     **/
    public function setSettings($param)
    {
        if (!$this->initialized) {
            $this->data['settings'] = $param;
        } else {
            $this->data['settings'] = serialize($param);
            $this->dirty['settings'] = true;
        }
    }
    // }}}
    // {{{ getSettings()
    /**
     * @brief getSettings
     *
     * @param mixed
     * @return void
     **/
    public function getSettings()
    {
        $settings = [];
        if (!empty($this->data['settings'])) {
            $settings = unserialize($this->data['settings']);
        }
        return $settings;
    }
    // }}}

    // {{{ save()
    /**
     * save a user object
     *
     * @public
     *
     * @return      auth_user
     */
    public function save() {
        $fields = [];
        $params = [];
        $primary = self::$primary[0];
        $isNew = $this->data[$primary] === null;

        if ($isNew) {
            $this->dateRegistered = date("Y-m-d H:i:s");
            $this->loginTimeout = 0;
        }

        $dirty = array_keys(array_intersect_key($this->dirty, self::$fields), true);
        if (count($dirty) > 0) {
            if ($isNew) {
                $query = "INSERT INTO {$this->pdo->prefix}_auth_user";
            } else {
                $query = "UPDATE {$this->pdo->prefix}_auth_user";
            }
            foreach ($dirty as $key) {
                $fields[] = "$key=:$key";
                $params[$key] = $this->data[$key];
            }
            $query .= " SET " . implode(",", $fields);

            if (!$isNew) {
                $query .= " WHERE $primary=:$primary";
                $params[$primary] = $this->data[$primary];
            }

            $cmd = $this->pdo->prepare($query);
            $success = $cmd->execute($params);

            if ($isNew) {
                $this->data[$primary] = $this->pdo->lastInsertId();
            }

            if ($success) {
                foreach (static::$fields as $key => $default) {
                    $this->dirty[$key] = false;
                }
            }
        }
    }
    // }}}

    // {{{ getUseragent()
    /**
     * gets a user-object by sid (session-id) directly from database
     *
     * @public
     *
     * @param       Depage\Db\Pdo     $pdo        pdo object for database access
     * @param       string  $sid        session id
     *
     * @return      auth_user
     */
    public function getUseragent() {
        $parser = \UAParser\Parser::create();
        $result = $parser->parse($this->useragent);

        return $result->toString();
    }
    // }}}

    // {{{ onLogout
    /**
     * Logout
     *
     * Called when the user is logged out.
     *
     * Override in inheriting classes to provide session end functionality.
     *
     * @param $session_id
     *
     * @return void
     */
    public function onLogout($sid) {
    }
    // }}}
    // {{{ onLoad()
    /**
     * @brief onLoad
     *
     * @param mixed
     * @return void
     **/
    protected function onLoad()
    {
        // can be overridden by child class
    }
    // }}}

}

/* vim:set ft=php sw=4 sts=4 fdm=marker : */
