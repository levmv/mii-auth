
Sql tables example:
```sql
CREATE TABLE `users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(128) NOT NULL,
  `password` char(60) CHARACTER SET ascii NOT NULL DEFAULT '',
  `name` varchar(64) NOT NULL,
  `surname` varchar(64) NOT NULL,
  `logins` int(10) unsigned NOT NULL DEFAULT 0,
  `last_login` int(10) unsigned DEFAULT NULL,
  `roles` int(10) unsigned NOT NULL,
  `created` int(10) unsigned NOT NULL,
  `verify_date` int(10) unsigned DEFAULT NULL,
  `verify_code` varchar(128) CHARACTER SET ascii DEFAULT '',
  `email_verified` int(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE `user_tokens` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) unsigned NOT NULL,
  `token` char(32) CHARACTER SET ascii NOT NULL DEFAULT '',
  `expires` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_token` (`token`),
  KEY `fk_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE `user_socials` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `network` enum('fb','vk','ok','ggl','ya','gh', 'ig') NOT NULL DEFAULT 'vk',
  `identity` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `identity` (`identity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```
