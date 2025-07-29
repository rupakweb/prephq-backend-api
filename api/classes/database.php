<?php
class Database
{
    private $server_name = 'localhost';
    private $database_username = 'u733794648_prephq';
    private $database_password = 'prepHQ123';
    private $database_name = 'u733794648_prephq';
    private $connection = null;

    public function register($user)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
        $sql = $this->connection->prepare(
            'INSERT INTO user (`name`, `lastname`, `username`, `password`, `email`, `status`, `created_date`) VALUES (?,?,?,?,?,?,?)'
        );
        $sql->bind_param(
            'sssssis',
            $user['name'],
            $user['lastname'],
            $user['username'],
            $user['password'],
            $user['email'],
            $user['status'],
            $user['created_date']
        );
        if ($sql->execute()) {
            $id = $this->connection->insert_id;
            $sql->close();
            $this->connection->close();
            return $id;
        }
        $sql->close();
        $this->connection->close();
        return false;
    }

    public function generateConfirmCode($user_id)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
        $sql = $this->connection->prepare(
            'INSERT INTO `accountconfirm`(`user_id`, `code`) VALUES(?,?) ON DUPLICATE KEY UPDATE    
            code=?'
        );
        $code = rand(11111, 99999);
        $sql->bind_param('iss', $user_id, $code, $code);
        if ($sql->execute()) {
            $sql->close();
            $this->connection->close();
            return $code;
        }
        $sql->close();
        $this->connection->close();
        return false;
    }

    public function confirmCode($user_id, $code)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
        $sql = $this->connection->prepare(
            'SELECT * FROM `accountconfirm` WHERE user_id=? AND code=?'
        );
        $sql->bind_param('is', $user_id, $code);
        $sql->execute();
        $result = $sql->get_result();
        if ($result->num_rows > 0) {
            $sql->close();
            $this->connection->close();
            return true;
        }
        $sql->close();
        $this->connection->close();
        return false;
    }

    public function activeUser($user_id)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
        $sql = $this->connection->prepare(
            'UPDATE `user` SET `status` = 1 WHERE id=?'
        );
        $sql->bind_param('i', $user_id);
        if ($sql->execute()) {
            $sql->close();
            $this->connection->close();
            return true;
        }
        $sql->close();
        $this->connection->close();
        return false;
    }

    public function loginUser($username, $password)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
        $sql = $this->connection->prepare(
            'SELECT * FROM `user` WHERE username=? AND password=?'
        );
        $sql->bind_param('ss', $username, $password);
        $sql->execute();
        $result = $sql->get_result();
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $sql->close();
            $this->connection->close();
            return $user;
        }
        $sql->close();
        $this->connection->close();
        return false;
    }

    public function getUserByUsernameOrEmail($username)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
        $sql = $this->connection->prepare(
            'SELECT DISTINCT * FROM `user` WHERE username=? OR email=?'
        );
        $sql->bind_param('ss', $username, $username);
        $sql->execute();
        $result = $sql->get_result();
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $sql->close();
            $this->connection->close();
            return $user;
        }
        $sql->close();
        $this->connection->close();
        return false;
    }

    public function updateUser($user)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
        if (isset($user['password']) && !empty($user['password'])) {
            $sql = $this->connection->prepare(
                'UPDATE `user` SET `name` = ?, `lastname` = ?, `username` = ?, `password` = ?, `email` = ? WHERE id = ?'
            );
            $sql->bind_param(
                'sssssi',
                $user['name'],
                $user['lastname'],
                $user['username'],
                $user['password'],
                $user['email'],
                $user['id']
            );
        } else {
            // mit password
            $sql = $this->connection->prepare(
                'UPDATE `user` SET `name` = ?, `lastname` = ?, `username` = ?, `email` = ? WHERE id = ?'
            );
            $sql->bind_param(
                'ssssi',
                $user['name'],
                $user['lastname'],
                $user['username'],
                $user['email'],
                $user['id']
            );
        }
        if ($sql->execute()) {
            $sql->close();
            $this->connection->close();
            return true;
        }
        $sql->close();
        $this->connection->close();
        return false;
    }
    public function saveContactMessage($contact)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
    
        $sql = $this->connection->prepare(
            'INSERT INTO `contact_messages` (`firstname`, `lastname`, `email`, `message`) VALUES (?, ?, ?, ?)'
        );
    
        $sql->bind_param(
            'ssss',
            $contact['firstname'],
            $contact['lastname'],
            $contact['email'],
            $contact['message']
        );
    
        if ($sql->execute()) {
            $insert_id = $this->connection->insert_id;
            $sql->close();
            $this->connection->close();
            return $insert_id;
        }
    
        $sql->close();
        $this->connection->close();
        return false;
    }
    
    public function saveNewsletterSubscriber($email)
    {
        $this->connection = new mysqli(
            $this->server_name,
            $this->database_username,
            $this->database_password,
            $this->database_name
        );
        $this->connection->set_charset('utf8');
        
        // First: Check if email already subscribed
        $check = $this->connection->prepare(
            'SELECT id FROM newsletter_subscribers WHERE email = ?'
        );
        $check->bind_param('s', $email);
        $check->execute();
        $check->store_result();
    
        if ($check->num_rows > 0) {
            $check->close();
            $this->connection->close();
            return 'exists'; // <-- return status for duplicate
        }
        $check->close();
    
        // Proceed to insert new email
        $sql = $this->connection->prepare(
            'INSERT INTO newsletter_subscribers (email, status, subscribed_at) VALUES (?, ?, ?)'
        );
    
        $status = 1;
        $subscribed_at = date('Y-m-d H:i:s');
        $sql->bind_param('sis', $email, $status, $subscribed_at);
    
        if ($sql->execute()) {
            $insert_id = $this->connection->insert_id;
            $sql->close();
            $this->connection->close();
            return $insert_id;
        }
    
        $sql->close();
        $this->connection->close();
        return false;
    }

    
}