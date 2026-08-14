CREATE TABLE `botHealth` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pairingId` int NOT NULL,
	`connectionStatus` enum('connected','degraded','offline') NOT NULL DEFAULT 'connected',
	`lastHeartbeat` timestamp,
	`uptimeSeconds` int NOT NULL DEFAULT 0,
	`cpuPercent` decimal(5,2) NOT NULL DEFAULT '0.00',
	`ramMb` int NOT NULL DEFAULT 0,
	`restartCount` int NOT NULL DEFAULT 0,
	`lastError` text,
	CONSTRAINT `botHealth_id` PRIMARY KEY(`id`),
	CONSTRAINT `botHealth_pairingId_unique` UNIQUE(`pairingId`)
);
--> statement-breakpoint
CREATE TABLE `bots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`slug` varchar(64) NOT NULL,
	`name` varchar(120) NOT NULL,
	`vendor` varchar(120) NOT NULL,
	`description` text NOT NULL,
	`capabilities` text NOT NULL,
	`status` enum('online','degraded','offline') NOT NULL DEFAULT 'online',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `bots_id` PRIMARY KEY(`id`),
	CONSTRAINT `bots_slug_unique` UNIQUE(`slug`)
);
--> statement-breakpoint
CREATE TABLE `docs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`slug` varchar(120) NOT NULL,
	`title` varchar(180) NOT NULL,
	`category` varchar(80) NOT NULL,
	`excerpt` text NOT NULL,
	`content` text NOT NULL,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `docs_id` PRIMARY KEY(`id`),
	CONSTRAINT `docs_slug_unique` UNIQUE(`slug`)
);
--> statement-breakpoint
CREATE TABLE `notifications` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`title` varchar(180) NOT NULL,
	`body` text NOT NULL,
	`read` boolean NOT NULL DEFAULT false,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `notifications_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `orders` (
	`id` int AUTO_INCREMENT NOT NULL,
	`orderId` varchar(32) NOT NULL,
	`userId` int NOT NULL,
	`planId` int NOT NULL,
	`status` enum('pending','approved','provisioned','rejected') NOT NULL DEFAULT 'pending',
	`amountSd` decimal(12,2) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `orders_id` PRIMARY KEY(`id`),
	CONSTRAINT `orders_orderId_unique` UNIQUE(`orderId`)
);
--> statement-breakpoint
CREATE TABLE `pairings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`botId` int NOT NULL,
	`phoneNumber` varchar(32) NOT NULL,
	`pairingCode` varchar(32),
	`status` enum('waiting','code_generated','connected','failed','disconnected') NOT NULL DEFAULT 'waiting',
	`lastHeartbeat` timestamp,
	`connectedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `pairings_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `panelPlans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(120) NOT NULL,
	`tier` varchar(80) NOT NULL,
	`description` text NOT NULL,
	`priceSd` decimal(12,2) NOT NULL,
	`specs` text NOT NULL,
	`active` boolean NOT NULL DEFAULT true,
	CONSTRAINT `panelPlans_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `referrals` (
	`id` int AUTO_INCREMENT NOT NULL,
	`referrerId` int NOT NULL,
	`referredUserId` int NOT NULL,
	`rewardSd` decimal(12,2) NOT NULL DEFAULT '5.00',
	`status` enum('pending','rewarded') NOT NULL DEFAULT 'pending',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `referrals_id` PRIMARY KEY(`id`),
	CONSTRAINT `referrals_referredUserId_unique` UNIQUE(`referredUserId`)
);
--> statement-breakpoint
CREATE TABLE `supportTickets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`category` varchar(80) NOT NULL,
	`botName` varchar(120),
	`phoneNumber` varchar(32),
	`subject` varchar(180) NOT NULL,
	`description` text NOT NULL,
	`screenshotUrl` text,
	`status` enum('open','in_progress','resolved','closed') NOT NULL DEFAULT 'open',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `supportTickets_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `telegramKeys` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`botId` int NOT NULL,
	`keyValue` varchar(96) NOT NULL,
	`telegramUsername` varchar(128),
	`durationDays` int NOT NULL,
	`expiresAt` timestamp NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `telegramKeys_id` PRIMARY KEY(`id`),
	CONSTRAINT `telegramKeys_keyValue_unique` UNIQUE(`keyValue`)
);
--> statement-breakpoint
CREATE TABLE `ticketMessages` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ticketId` int NOT NULL,
	`authorId` int NOT NULL,
	`message` text NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ticketMessages_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vouchers` (
	`id` int AUTO_INCREMENT NOT NULL,
	`code` varchar(64) NOT NULL,
	`amount` decimal(12,2) NOT NULL,
	`redeemedBy` int,
	`redeemedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vouchers_id` PRIMARY KEY(`id`),
	CONSTRAINT `vouchers_code_unique` UNIQUE(`code`)
);
--> statement-breakpoint
CREATE TABLE `walletTransactions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`type` enum('credit','panel_purchase','key_purchase','voucher_redemption','referral_reward') NOT NULL,
	`amount` decimal(12,2) NOT NULL,
	`description` varchar(255) NOT NULL,
	`reference` varchar(96),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `walletTransactions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `users` ADD `sdBalance` decimal(12,2) DEFAULT '0.00' NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `referralCode` varchar(32);--> statement-breakpoint
ALTER TABLE `users` ADD CONSTRAINT `users_referralCode_unique` UNIQUE(`referralCode`);