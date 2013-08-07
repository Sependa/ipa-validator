//
//  main.m
//  IPAValidator
//
//  Created by Pawel Dudek on 8/7/13.
//  Copyright (c) 2013 Taptera. All rights reserved.
//

#import <Foundation/Foundation.h>

NSString *getIPAPath(NSString *currentDirectoryPath);

void unzipIPAAtPathToPath(NSString *currentDirectoryPath, NSString *fullIpaPath);

NSString *getSecurityCheckResults(NSString *appDirectory);

NSString *getResultsFromTask(NSTask *task, NSUInteger dataAdjustment, BOOL useErrorPipe);

NSString *getProfileEntitlementsCheckResults(NSString *appDirectory);

NSString *getSecurityEntitlementsCheckResults(NSString *appDirectory);

NSDictionary *securityEntitlementsFromAppAthPath(NSString *appDirectory);

void verifyEntitlementsValidity(NSDictionary *dictionary, NSMutableArray *detectedErrors);

NSDictionary *getProfileEntitlementsFromAppAtPath(NSString *appDirectory);

NSDictionary *getPlistDictionaryFromString(NSString *string);

void verifySecurityEntitlementsMathProfileEntitlements(NSDictionary *securityEntitlements, NSDictionary *profileEntitlements, NSMutableArray *detectedErrors, NSMutableArray *detailedDescriptions);

void checkSigningAuthoritiesForAppAtPath(NSString *appDirectory);

void validateIPACodesign(NSString *appDirectory, BOOL verbose);

void ConsoleLog(NSString *formatString, ...) {
    va_list args;
    va_start(args, formatString);

    NSString *arguments = [[NSString alloc] initWithFormat:formatString arguments:args];
    printf("%s\n", [arguments cStringUsingEncoding:NSASCIIStringEncoding]);

    va_end(args);
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSMutableArray *arguments = [NSMutableArray array];

        for (int i = 0; i < argc; i++) {
            NSString *str = [NSString stringWithUTF8String:argv[i]];
            [arguments addObject:str];
        }

        if ([arguments containsObject:@"-help"] || [arguments count] == 0) {

            ConsoleLog(@"Usage:\n");

            NSMutableArray *usage = [NSMutableArray array];
            [usage addObject:@"-help       Display this message"];
            [usage addObject:@"-csa        Display code signing authorities"];
            [usage addObject:@"-validate   Validates whether the IPA is a valid IPA"];
            [usage addObject:@"--verbose    Display additional information during validation"];

            for (NSString *usageString in usage) {
                ConsoleLog(@"* %@", usageString);
            }

            ConsoleLog(@"");

            exit(0);
        }

        NSFileManager *fileManager = [NSFileManager defaultManager];

        NSString *currentDirectoryPath = [fileManager currentDirectoryPath];
        NSString *ipaFile = getIPAPath(currentDirectoryPath);

        NSString *fullIpaPath = [currentDirectoryPath stringByAppendingPathComponent:ipaFile];

        if (ipaFile == nil) {
            [NSException raise:@"Warning! No ipa file found in current directory." format:nil];
        }

        unzipIPAAtPathToPath(currentDirectoryPath, fullIpaPath);

        NSString *payloadPath = [currentDirectoryPath stringByAppendingPathComponent:@"Payload"];
        NSArray *payloadContents = [fileManager contentsOfDirectoryAtPath:payloadPath error:nil];
        NSString *appDirectory = [payloadPath stringByAppendingPathComponent:[payloadContents lastObject]];

        if ([arguments containsObject:@"-csa"]) {
            checkSigningAuthoritiesForAppAtPath(appDirectory);
        }

        if ([arguments containsObject:@"-validate"]) {
            BOOL verbose = [arguments containsObject:@"--verbose"];
            validateIPACodesign(appDirectory, verbose);
        }

        [fileManager removeItemAtPath:payloadPath error:nil];
    }
    return 0;
}

#pragma mark - Checking authorities

void checkSigningAuthoritiesForAppAtPath(NSString *appDirectory) {
    NSString *securityCheckResults = getSecurityCheckResults(appDirectory);
    NSArray *componentsSeparatedByString = [securityCheckResults componentsSeparatedByString:@"\n"];
    NSArray *authorities = [componentsSeparatedByString filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(id evaluatedObject, NSDictionary *bindings) {
        return [evaluatedObject hasPrefix:@"Authority="];
    }]];

    ConsoleLog(@"Detected code signing authorities: \n\n%@", [authorities componentsJoinedByString:@"\n"]);
    ConsoleLog(@"");
}

#pragma mark - Validation

void verifySecurityEntitlementsMathProfileEntitlements(NSDictionary *securityEntitlements, NSDictionary *profileEntitlements, NSMutableArray *detectedErrors, NSMutableArray *detailedDescriptions) {
    NSString *securityAppId = securityEntitlements[@"application-identifier"];
    NSString *profileAppId = profileEntitlements[@"application-identifier"];

    if ([securityAppId isEqualToString:profileAppId] == NO) {
        [detectedErrors addObject:@"app id in codesign did not match app id in embedded profile"];
        [detailedDescriptions addObject:[NSString stringWithFormat:@"There's a mismatch between app ids. This is usually caused when an IPA was resigned using "
                                                                           "a certificate from a different org than the original certificate"
                                                                           "\nApp id in codesign: %@\nApp id in embedded profile: %@",
                                                                   profileAppId, securityAppId]];
    }

    NSArray *securityKeychainAccessGroups = securityEntitlements[@"keychain-access-groups"];
    NSArray *profileKeychainAccessGroups = profileEntitlements[@"keychain-access-groups"];

    if ([securityKeychainAccessGroups isEqualToArray:profileKeychainAccessGroups] == NO) {
        [detectedErrors addObject:@"Keychain access groups in codesign did not match keychain access groups in embedded profile"];

        [detailedDescriptions addObject:[NSString stringWithFormat:@"There's a mismatch between keychain access groups. This is usually caused when an IPA was resigned using "
                                                                           "a certificate from a different org than the original certificate"
                                                                           "\nKeychain access groups in codesign: %@\nKeychain access groups in embedded profile: %@",
                                                                   securityKeychainAccessGroups,
                                                                   profileKeychainAccessGroups]];
    }
}

void verifyEntitlementsValidity(NSDictionary *dictionary, NSMutableArray *detectedErrors) {
    NSNumber *getTaskAllow = dictionary[@"get-task-allow"];
    if ([getTaskAllow boolValue] == YES) {
        [detectedErrors addObject:@"get-task-allow is set to YES, releases builds should have this entitlement set to false"];
    }
}

void validateIPACodesign(NSString *appDirectory, BOOL verbose) {
    NSDictionary *profileEntitlements = getProfileEntitlementsFromAppAtPath(appDirectory);
    NSDictionary *securityEntitlements = securityEntitlementsFromAppAthPath(appDirectory);

    NSMutableArray *detectedErrors = [NSMutableArray array];
    NSMutableArray *detailedDescriptions = nil;
    if (verbose) {
        detailedDescriptions = [NSMutableArray array];
    }

    verifyEntitlementsValidity(securityEntitlements, detectedErrors);

    if (profileEntitlements) {
        verifySecurityEntitlementsMathProfileEntitlements(securityEntitlements, profileEntitlements, detectedErrors, detailedDescriptions);
    }
    else {
        [detectedErrors addObject:@"Application entitlements are missing from codesign."];
        [detailedDescriptions addObject:@"The app can install without valid entitlements, however access to keychain and iCloud "
                "will be unavailable. This might cause unexpected behavior."];
    }

    if (detectedErrors.count > 0) {
        ConsoleLog(@"WARNING! This IPA is not a validly signed IPA. Detected errors:");
        ConsoleLog(@"");
        for (NSString *detectedError in detectedErrors) {
            ConsoleLog(@"* %@", detectedError);
        }
        ConsoleLog(@"");

        if (detailedDescriptions) {
            ConsoleLog(@"Hopefully helpful hints:");
            ConsoleLog(@"");

            for (NSString *description in detailedDescriptions) {
                ConsoleLog(@"* %@", description);
                ConsoleLog(@"");
            }
            ConsoleLog(@"");
        }
    }
}

#pragma mark - Getting entitlements data

NSDictionary *getProfileEntitlementsFromAppAtPath(NSString *appDirectory) {
    NSString *entitlementsCheckResults = getProfileEntitlementsCheckResults(appDirectory);
    NSDictionary *dictionary = getPlistDictionaryFromString(entitlementsCheckResults);
    return dictionary;
}

NSDictionary *securityEntitlementsFromAppAthPath(NSString *appDirectory) {
    NSString *securityEntitlementsCheckResults = getSecurityEntitlementsCheckResults(appDirectory);
    NSDictionary *plist = getPlistDictionaryFromString(securityEntitlementsCheckResults);

    NSDictionary *dictionary = plist[@"Entitlements"];
    return dictionary;
}

#pragma mark - Helpers

NSDictionary *getPlistDictionaryFromString(NSString *string) {
    NSData *plistData = [string dataUsingEncoding:NSUTF8StringEncoding];

    NSDictionary *plist = [NSPropertyListSerialization propertyListFromData:plistData
                                                           mutabilityOption:NSPropertyListImmutable format:nil
                                                           errorDescription:nil];
    return plist;
}

#pragma mark - Specific methods

NSString *getSecurityCheckResults(NSString *appDirectory) {
    NSTask *securityCheckTask = [[NSTask alloc] init];
    [securityCheckTask setLaunchPath:@"/usr/bin/codesign"];
    [securityCheckTask setArguments:@[@"-dvvv", appDirectory]];

    NSString *securityCheckResult = getResultsFromTask(securityCheckTask, 0, YES);
    return securityCheckResult;
}

NSString *getProfileEntitlementsCheckResults(NSString *appDirectory) {
    NSTask *securityCheckTask = [[NSTask alloc] init];
    [securityCheckTask setLaunchPath:@"/usr/bin/codesign"];
    [securityCheckTask setArguments:@[@"-d", @"--entitlements", @"-", appDirectory]];

    NSString *profileEntitlements = getResultsFromTask(securityCheckTask, 8, NO);
    return profileEntitlements;
}

NSString *getSecurityEntitlementsCheckResults(NSString *appDirectory) {
    NSTask *securityCheckTask = [[NSTask alloc] init];
    [securityCheckTask setLaunchPath:@"/usr/bin/security"];
    [securityCheckTask setArguments:@[@"cms", @"-D", @"-i", [appDirectory stringByAppendingPathComponent:@"embedded.mobileprovision"]]];

    NSString *profileEntitlements = getResultsFromTask(securityCheckTask, 0, NO);
    return profileEntitlements;
}

#pragma mark - Generic task methods

NSString *getResultsFromTask(NSTask *task, NSUInteger dataAdjustment, BOOL useErrorPipe) {
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    if (useErrorPipe) {
        [task setStandardError:pipe];
    }
    else {
        //silence the command line output
        [task setStandardError:[NSPipe pipe]];
    }
    __block NSFileHandle *handle = [pipe fileHandleForReading];
    __block NSString *securityCheckResult = nil;

//    NSLog(@"Running command \"%@ %@\"", [task launchPath], [[task arguments] componentsJoinedByString:@" "]);

    [task setTerminationHandler:^(NSTask *terminatedTask) {
        NSData *availableData = [handle availableData];
        NSUInteger length = [availableData length];

        if (length >= dataAdjustment) {
            NSData *subdataWithRange = [availableData subdataWithRange:NSMakeRange(dataAdjustment, length - dataAdjustment)];
            securityCheckResult = [[NSString alloc] initWithData:subdataWithRange encoding:NSASCIIStringEncoding];
        }
    }];

    [task launch];
    [task waitUntilExit];
    return securityCheckResult;
}

#pragma mark - Setup helpers

void unzipIPAAtPathToPath(NSString *currentDirectoryPath, NSString *fullIpaPath) {
    NSTask *unzipTask = [[NSTask alloc] init];
    [unzipTask setLaunchPath:@"/usr/bin/unzip"];

    [unzipTask setArguments:@[@"-q", fullIpaPath, @"-d", currentDirectoryPath]];

    [unzipTask launch];
    [unzipTask waitUntilExit];
}

NSString *getIPAPath(NSString *currentDirectoryPath) {
    NSFileManager *fileManager = [NSFileManager defaultManager];

    NSArray *contentsOfDirectory = [fileManager contentsOfDirectoryAtPath:currentDirectoryPath error:nil];
    NSArray *ipaFiles = [contentsOfDirectory filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(id evaluatedObject, NSDictionary *bindings) {
        return [evaluatedObject hasSuffix:@".ipa"];
    }]];

    NSString *ipaFile = [ipaFiles lastObject];
    return ipaFile;
}

