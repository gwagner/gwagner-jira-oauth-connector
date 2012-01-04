<?php
/**
 * Created by JetBrains PhpStorm.
 * User: gwagner
 * Date: 1/4/12
 * Time: 9:32 AM
 * To change this template use File | Settings | File Templates.
 */

class JiraOAuthConnector
{
    protected $config;
    protected $consumer;
    protected $token;
    protected $jira_domain;
    protected $jira_port;
    protected $automatic_revalidate_user = true;
    protected $rsa_path = './rsa_keys/id_rsa';
    protected $callback_path = "/index/confirm/";

    protected $consumer_key = 'SECRET_KEY_THAT_SHOULD_BE_CHANGED';
    protected $consumer_secret = 'SECRET_KEY_THAT_SHOULD_BE_CHANGED_AND_SHOULD_BE_DIFFERENT_THAN_THE_OTHER_KEY';
    protected $hash_keys = true;


    public function __construct()
    {
        if($this->hash_keys)
        {
            $this->consumer_key = md5($this->consumer_key);
            $this->consumer_secret = md5($this->consumer_secret);
        }

        $key = new Zend_Crypt_Rsa(
            array('pemPath' => $this->rsa_path)
        );

        $this->config = array(
            'callbackUrl' => 'http://'.$_SERVER['HTTP_HOST'].$this->callback_path,
            'siteUrl' => 'http://'.$this->jira_domain.':'.$this->jira_port,
            'requestTokenUrl' => 'http://'.$this->jira_domain.':'.$this->jira_port.'/plugins/servlet/oauth/request-token',
            'accessTokenUrl' => 'http://'.$this->jira_domain.':'.$this->jira_port.'/plugins/servlet/oauth/access-token',
            'authorizeUrl' => 'http://'.$this->jira_domain.':'.$this->jira_port.'/plugins/servlet/oauth/authorize',
            'consumerKey' => $this->consumer_key,
            'consumerSecret' => $this->consumer_secret,
            'rsaPrivateKey' => $key->getPrivateKey(),
            'rsaPublicKey' => $key->getPublicKey(),
            'signatureMethod' => 'RSA-SHA1',
        );
        $this->consumer = new Zend_Oauth_Consumer($this->config);

    }

    public function validateOAuthAccess()
    {
        $_SESSION['JIRA_REQUEST_TOKEN'] = serialize($this->consumer->getRequestToken());

        $this->consumer->redirect();
    }

    public function confirm()
    {
        if($_SESSION['JIRA_REQUEST_TOKEN'])
        {
            $_SESSION['JIRA_ACCESS_TOKEN'] = serialize($this->consumer->getAccessToken(
                $_GET,
                unserialize($_SESSION['JIRA_REQUEST_TOKEN'])
            ));
        }
        else
            die('Bad Request Token');
    }

    /**
     * @return Zend_Oauth_Client
     */
    public function getHttpClient()
    {
        if(isset($this->token) && $this->token instanceof Zend_Oauth_Token_Request)
            return $this->token->getHttpClient($this->config);

        if(!isset($_SESSION['JIRA_ACCESS_TOKEN']))
            die(__LINE__);//$this->validateOAuthAccess();

        $token = unserialize($_SESSION['JIRA_ACCESS_TOKEN']);

        if(!($token instanceof Zend_Oauth_Token_Request) && !($token instanceof Zend_Oauth_Token_Access))
            die(__LINE__);//$this->validateOAuthAccess();

        $this->token = $token;

        return $token->getHttpClient($this->config);
    }

    public function getIssue($issue_id)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id);
        $client->setMethod(Zend_Http_Client::GET);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function getIssueTransitions($issue_id)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id.'/transitions');
        $client->setMethod(Zend_Http_Client::GET);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function postIssueTransitions($issue_id, $fields, $comment, $transition = false)
    {
        if(!$transition)
        {
            $transitions = $this->getIssueTransitions($issue_id);
            end($transitions);
            $transition = key($transitions) + 1;
        }

        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id.'/transitions');
        $client->setMethod(Zend_Http_Client::POST);
        $client->setParameterPost(
            json_encode(
                array(
                    'transition' => $transition,
                    'fields' => $fields,
                    'comment' => $comment
                )
            )
        );
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return $response->getBody();
    }

    public function getIssueVotes($issue_id)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id.'/votes');
        $client->setMethod(Zend_Http_Client::GET);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function postIssueVotes($issue_id)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id.'/votes');
        $client->setMethod(Zend_Http_Client::POST);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function deleteIssueVotes($issue_id)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id.'/votes');
        $client->setMethod(Zend_Http_Client::DELETE);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function getIssueWatchers($issue_id)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id.'/watchers');
        $client->setMethod(Zend_Http_Client::GET);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function postIssueWatcher($issue_id, $username)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id.'/watchers');
        $client->setParameterPost(json_encode($username));
        $client->setMethod(Zend_Http_Client::POST);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function deleteIssueWatcher($issue_id, $username)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/issue/'.$issue_id.'/watchers');
        $client->setParameterPost('username', $username);
        $client->setMethod(Zend_Http_Client::DELETE);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function searchGroups($query)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/groups/picker');
        $client->setParameterPost('query', $query);
        $client->setMethod(Zend_Http_Client::GET);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function getMySession()
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/auth/1/session');
        $client->setMethod(Zend_Http_Client::GET);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function createVersion($description, $name, $userReleaseDate, $project, $releaseDate, $archived = false, $released = false)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/version');
        $client->setParameterPost(
            json_encode(
                array(
                    'description' => $description,
                    'name' => $name,
                    'userReleaseDate' => $userReleaseDate,
                    'project' => $project,
                    'releaseDate' => $releaseDate,
                    'archived' => $archived,
                    'released' => $released
                )
            )
        );
        $client->setMethod(Zend_Http_Client::POST);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function deleteVersion($version_id, $moveFixIssuesTo = false, $moveAffectedIssuesTo = false)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/version/'.$version_id);

        if($moveFixIssuesTo)
            $client->setParameterPost('moveFixIssuesTo', $moveFixIssuesTo);

        if($moveAffectedIssuesTo)
            $client->setParameterPost('moveAffectedIssuesTo', $moveAffectedIssuesTo);

        $client->setMethod(Zend_Http_Client::DELETE);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function getVersion($version_id)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/version/'.$version_id);
        $client->setMethod(Zend_Http_Client::GET);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function modifyVersion($version_id, $description, $name, $userReleaseDate, $project, $releaseDate, $archived = false, $released = false)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/version/'.$version_id);

        /* @todo: Modify this so that we can pick and choose the params we want to send to modify a version */
        $client->setParameterPost(
            json_encode(
                array(
                    'self' => 'http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/version/'.$version_id,
                    'id' => $version_id,
                    'description' => $description,
                    'name' => $name,
                    'userReleaseDate' => $userReleaseDate,
                    'project' => $project,
                    'releaseDate' => $releaseDate,
                    'archived' => $archived,
                    'released' => $released
                )
            )
        );
        $client->setMethod(Zend_Http_Client::POST);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function getCountIssuesRelatedToVersion($version_id)
    {
        $client = $this->getHttpClient();

        $client->setUri('http://'.$this->jira_domain.':'.$this->jira_port.'/rest/api/2.0.alpha1/version/'.$version_id.'/relatedIssueCounts');
        $client->setMethod(Zend_Http_Client::GET);
        $response = $client->request();

        if($response->getStatus() == 401)
        {
            if($this->automatic_revalidate_user)
                $this->validateOAuthAccess();
            else
                die('Your user session has expired.');
        }

        return json_decode($response->getBody(), true);
    }

    public function moveVersion($version_id)
    {
        /* @todo: support /api/2.0.alpha1/version/{id}/move in the code */
        die('This API call is not supported by this software yet');
    }

}