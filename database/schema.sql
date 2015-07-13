-- Create syntax for TABLE 'affiliates'
CREATE TABLE `sso_users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) DEFAULT NULL,
  `password` varchar(100) DEFAULT NULL,
  `email_address` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;

-- Create syntax for TABLE 'sso_access_tokens'
CREATE TABLE `sso_access_tokens` (
  `oauth_token` varchar(255) NOT NULL DEFAULT '',
  `client_id` varchar(20) NOT NULL,
  `user_id` int(11) unsigned NOT NULL,
  `expires` int(11) NOT NULL,
  `scope` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`oauth_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Create syntax for TABLE 'sso_auth_codes'
CREATE TABLE `sso_auth_codes` (
  `code` varchar(255) NOT NULL DEFAULT '',
  `client_id` varchar(20) NOT NULL,
  `user_id` varchar(20) NOT NULL,
  `redirect_uri` varchar(200) NOT NULL,
  `expires` int(11) NOT NULL,
  `scope` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Create syntax for TABLE 'sso_clients'
CREATE TABLE `sso_clients` (
  `client_id` varchar(20) NOT NULL,
  `client_secret` varchar(200) NOT NULL,
  `redirect_uri` varchar(200) NOT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Create syntax for TABLE 'sso_refresh_tokens'
CREATE TABLE `sso_refresh_tokens` (
  `oauth_token` varchar(255) NOT NULL DEFAULT '',
  `refresh_token` varchar(255) NOT NULL DEFAULT '',
  `client_id` varchar(20) NOT NULL,
  `user_id` int(11) unsigned NOT NULL,
  `expires` int(11) NOT NULL,
  `scope` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`oauth_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
