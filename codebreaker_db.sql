-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 01, 2026 at 01:45 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `codebreaker_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `action_logs`
--

CREATE TABLE `action_logs` (
  `id` int(11) NOT NULL,
  `username` varchar(50) DEFAULT NULL,
  `action` varchar(100) DEFAULT NULL,
  `timestamp` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `action_logs`
--

INSERT INTO `action_logs` (`id`, `username`, `action`, `timestamp`) VALUES
(17, 'admin', 'added user: user1', '2026-04-14 04:12:30'),
(18, 'user1', 'updated email address', '2026-04-14 04:13:49'),
(19, 'user1', 'logged out', '2026-04-14 04:13:59'),
(20, 'admin', 'added user: user2', '2026-04-14 04:14:34'),
(21, 'admin', 'unlocked account #6', '2026-04-14 04:15:29'),
(22, 'admin', 'unlocked account #6', '2026-04-14 04:16:24'),
(23, 'user2', 'logged out', '2026-04-14 04:18:45'),
(24, 'admin', 'unlocked account #6', '2026-04-14 04:19:42'),
(25, 'admin', 'unlocked account #6', '2026-04-14 04:20:50'),
(26, 'admin', 'unlocked account #6', '2026-04-14 04:21:25'),
(27, 'admin', 'unlocked account #6', '2026-04-14 04:23:20'),
(28, 'admin', 'unlocked account #6', '2026-04-14 04:24:13'),
(29, 'admin', 'unlocked account #6', '2026-04-14 04:26:13'),
(30, 'admin', 'added user: admin1', '2026-04-14 04:29:11'),
(31, 'admin', 'unlocked account #7', '2026-04-14 04:29:50'),
(32, 'admin', 'logged out', '2026-04-14 04:31:02'),
(33, 'admin1', 'unlocked account #6', '2026-04-14 04:31:59'),
(34, 'admin1', 'deleted user: admin1', '2026-04-14 04:33:12'),
(35, 'admin1', 'logged out', '2026-04-14 05:02:06'),
(36, 'user2', 'logged out', '2026-04-14 05:03:56'),
(37, 'user1', 'logged out', '2026-04-14 05:14:47'),
(38, 'admin', 'added user: admin2', '2026-04-14 05:15:17'),
(39, 'admin', 'unlocked account #8', '2026-04-14 05:16:05'),
(40, 'admin2', 'logged out', '2026-04-14 05:28:26'),
(41, 'admin', 'logged out', '2026-04-14 05:35:22'),
(42, 'admin', 'added user: user3 (user)', '2026-04-14 05:41:15'),
(43, 'admin', 'logged out', '2026-04-14 05:41:26'),
(44, 'user1', 'logged out', '2026-04-14 05:41:56'),
(45, 'admin', 'unlocked account #9', '2026-04-14 05:42:51'),
(46, 'admin', 'logged out', '2026-04-14 05:45:06'),
(47, 'admin2', 'unlocked account #6', '2026-04-14 05:47:30'),
(48, 'admin', 'logged out', '2026-04-30 14:25:19'),
(49, 'admin', 'logged out', '2026-04-30 14:43:52'),
(50, 'admin', 'deleted user: user1', '2026-04-30 14:46:54'),
(51, 'admin', 'deleted user: user2', '2026-04-30 14:46:57'),
(52, 'admin', 'deleted user: admin2', '2026-04-30 14:46:59'),
(53, 'admin', 'deleted user: user3', '2026-04-30 14:47:01'),
(54, 'admin', 'cleared all login logs', '2026-04-30 14:47:07'),
(55, 'admin', 'added user: dapu (user)', '2026-04-30 14:48:06'),
(56, 'admin', 'logged out', '2026-04-30 14:48:26'),
(57, 'dapu', 'logged out', '2026-04-30 14:54:36'),
(58, 'admin', 'added user: pusa (admin)', '2026-04-30 14:55:49'),
(59, 'admin', 'logged out', '2026-04-30 14:56:07'),
(60, 'pusa', 'logged out', '2026-04-30 14:57:11'),
(61, 'dapu', 'logged out', '2026-04-30 15:22:15'),
(62, 'admin', 'logged out', '2026-04-30 15:44:36'),
(63, 'admin', 'logged out', '2026-05-01 03:24:57'),
(64, 'dapu', 'logged out', '2026-05-01 03:34:19'),
(65, 'admin', 'cleared all login logs', '2026-05-01 03:35:55'),
(66, 'admin', 'logged out', '2026-05-01 03:39:55'),
(67, 'pusa', 'logged out', '2026-05-01 04:13:53'),
(68, 'admin', 'logged out', '2026-05-01 13:42:00');

-- --------------------------------------------------------

--
-- Table structure for table `login_logs`
--

CREATE TABLE `login_logs` (
  `id` int(11) NOT NULL,
  `username` varchar(50) DEFAULT NULL,
  `timestamp` datetime DEFAULT current_timestamp(),
  `status` enum('SUCCESS','FAILED') NOT NULL,
  `reason` varchar(100) DEFAULT NULL,
  `ip_address` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `login_logs`
--

INSERT INTO `login_logs` (`id`, `username`, `timestamp`, `status`, `reason`, `ip_address`) VALUES
(1, 'admin', '2026-05-01 03:55:08', 'FAILED', 'wrong password', '127.0.0.1'),
(2, 'pusa', '2026-05-01 04:12:32', 'SUCCESS', 'success', '127.0.0.1'),
(3, 'admin', '2026-05-01 13:41:35', 'SUCCESS', 'success', '127.0.0.1');

-- --------------------------------------------------------

--
-- Table structure for table `security_questions`
--

CREATE TABLE `security_questions` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `question` varchar(255) NOT NULL,
  `answer_hash` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `security_questions`
--

INSERT INTO `security_questions` (`id`, `user_id`, `question`, `answer_hash`) VALUES
(10, 1, 'code', '$2y$10$wB9Q0UxTjSpihmW.tfW.a.AEdDPHQ.5VKN3ClyzRS9HJhghHKuORC'),
(16, 10, 'code', '$2y$10$KvS0gFt2cJw5ymz7wR0FCuUFu2yL1J5AkgKCmET/XCGoOaCdwTVbK'),
(17, 11, 'code', '$2y$10$/WcsfcCBhYgY5/DRNF9rbuGr4Be3Iz6ARKgsWROrlmJFY6/gCRqlG');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `otp` varchar(6) DEFAULT NULL,
  `otp_expiration` datetime DEFAULT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('admin','user') DEFAULT 'user',
  `failed_attempts` int(11) DEFAULT 0,
  `lock_until` datetime DEFAULT NULL,
  `lockout_tier` int(11) NOT NULL DEFAULT 0,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `otp`, `otp_expiration`, `password_hash`, `role`, `failed_attempts`, `lock_until`, `lockout_tier`, `created_at`) VALUES
(1, 'admin', NULL, NULL, NULL, '$2y$10$n.4AZ5AWgp74uDF4fv33WeQ2DxZCjM8/A98KaYAPsvHXjyIAJsd/S', 'admin', 0, NULL, 0, '2026-04-14 04:11:32'),
(10, 'dapu', 'forcapstone1111@gmail.com', NULL, NULL, '$2y$10$Am5VbEm5i0SWPZkPSIybEeIYSOE0fQm2Mc3eLL.QOxLQG4eMAlAfq', 'user', 0, NULL, 0, '2026-04-30 14:48:06'),
(11, 'pusa', 'forcapstone1111@gmail.com', NULL, NULL, '$2y$10$UgbzPhOEXnO0MwYZKLWGdOwlUtNT40orLgbErVZ2WWvccE8drk29a', 'admin', 0, NULL, 0, '2026-04-30 14:55:49');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `action_logs`
--
ALTER TABLE `action_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `login_logs`
--
ALTER TABLE `login_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `security_questions`
--
ALTER TABLE `security_questions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `action_logs`
--
ALTER TABLE `action_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=69;

--
-- AUTO_INCREMENT for table `login_logs`
--
ALTER TABLE `login_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `security_questions`
--
ALTER TABLE `security_questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `security_questions`
--
ALTER TABLE `security_questions`
  ADD CONSTRAINT `security_questions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
