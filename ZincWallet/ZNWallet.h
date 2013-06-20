//
//  ZNWallet.h
//  ZincWallet
//
//  Created by Aaron Voisine on 5/12/13.
//  Copyright (c) 2013 zinc. All rights reserved.
//

#import <Foundation/Foundation.h>

#define walletSyncStartedNotification @"walletSyncStartedNotification"
#define walletSyncFinishedNotification @"walletSyncFinishedNotification"
#define walletSyncFailedNotification @"walletSyncFailedNotification"

@interface ZNWallet : NSObject

@property (nonatomic, strong) NSString *seedPhrase;
@property (nonatomic, strong) NSData *seed;
@property (nonatomic, readonly) uint64_t balance;
@property (nonatomic, readonly) NSString *receiveAddress;
@property (nonatomic, readonly) NSArray *recentTransactions; // sorted by date, most recent first
@property (nonatomic, strong) NSNumberFormatter *format;

+ (ZNWallet *)sharedInstance;

- (id)initWithSeedPhrase:(NSString *)phrase;
- (id)initWithSeed:(NSData *)seed;

- (void)generateRandomSeed;
- (void)synchronize;
- (NSString *)transactionFor:(uint64_t)amount to:(NSString *)address;
- (BOOL)containsAddress:(NSString *)address;
- (NSString *)stringForAmount:(uint64_t)amount;

@end