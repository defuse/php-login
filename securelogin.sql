-- phpMyAdmin SQL Dump
-- version 3.3.7deb6
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 18, 2011 at 12:23 PM
-- Server version: 5.1.49
-- PHP Version: 5.3.3-7+squeeze3

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `securelogin`
--

-- --------------------------------------------------------

--
-- Table structure for table `lockout`
--

CREATE TABLE IF NOT EXISTS `lockout` (
  `user` int(11) NOT NULL,
  `eventtime` bigint(20) NOT NULL,
  KEY `user` (`user`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `lockout_tokens`
--

CREATE TABLE IF NOT EXISTS `lockout_tokens` (
  `token` varchar(128) NOT NULL,
  `userid` int(11) NOT NULL,
  `createtime` bigint(20) NOT NULL,
  PRIMARY KEY (`token`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `login_fail_history`
--

CREATE TABLE IF NOT EXISTS `login_fail_history` (
  `user` int(11) NOT NULL,
  `ipaddr` varbinary(1024) NOT NULL,
  `time` bigint(20) NOT NULL,
  `agent` varbinary(4096) NOT NULL,
  KEY `user` (`user`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `login_history`
--

CREATE TABLE IF NOT EXISTS `login_history` (
  `user` int(11) NOT NULL,
  `ipaddr` varbinary(1024) NOT NULL,
  `time` bigint(20) NOT NULL,
  `agent` varbinary(4096) NOT NULL,
  KEY `user` (`user`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `reset_tokens`
--

CREATE TABLE IF NOT EXISTS `reset_tokens` (
  `token` varchar(128) NOT NULL,
  `userid` int(11) NOT NULL,
  `createtime` bigint(20) NOT NULL,
  PRIMARY KEY (`token`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `sdat`
--

CREATE TABLE IF NOT EXISTS `sdat` (
  `id` int(11) NOT NULL,
  `pkey` varchar(256) NOT NULL,
  `pvalue` longblob NOT NULL,
  KEY `pkey` (`pkey`),
  KEY `id` (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `smap`
--

CREATE TABLE IF NOT EXISTS `smap` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sesskeyhash` varbinary(256) NOT NULL,
  `datakey` varbinary(256) NOT NULL,
  `deleteafter` bigint(20) NOT NULL,
  `tag` varchar(250) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `sesskeyhash` (`sesskeyhash`),
  KEY `tag` (`tag`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=331663 ;

-- --------------------------------------------------------

--
-- Table structure for table `userauth`
--

CREATE TABLE IF NOT EXISTS `userauth` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(200) NOT NULL,
  `propercase` varchar(200) NOT NULL,
  `auth` varchar(256) NOT NULL,
  `salt` varchar(256) NOT NULL,
  `masterkey` varbinary(256) NOT NULL,
  `lockout` bigint(20) NOT NULL,
  `email` varchar(250) NOT NULL,
  `validated` tinyint(1) NOT NULL,
  `allowreset` tinyint(4) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=285 ;

-- --------------------------------------------------------

--
-- Table structure for table `user_data`
--

CREATE TABLE IF NOT EXISTS `user_data` (
  `user` int(11) NOT NULL,
  `pkey` varchar(200) NOT NULL,
  `pvalue` longblob NOT NULL,
  KEY `key` (`pkey`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `user_encrypted_data`
--

CREATE TABLE IF NOT EXISTS `user_encrypted_data` (
  `user` int(11) NOT NULL,
  `pkey` varchar(200) NOT NULL,
  `pvalue` longblob NOT NULL,
  KEY `key` (`pkey`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `validation_tokens`
--

CREATE TABLE IF NOT EXISTS `validation_tokens` (
  `token` varchar(128) NOT NULL,
  `userid` int(11) NOT NULL,
  `createtime` bigint(20) NOT NULL,
  PRIMARY KEY (`token`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
