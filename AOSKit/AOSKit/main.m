//
//  main.m
//  AOSKit
//
//  Created by Vincent Tan on 11/1/20.
//  Copyright © 2020 Vincent Tan. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AOSUtilities.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        NSLog(@"Hello, World!");
        
        NSLog(@"%@", [AOSUtilities currentComputerName]);
        NSLog(@"%@", [AOSUtilities machineUDID]);
        NSLog(@"%@", [AOSUtilities machineSerialNumber]);
        
        id one = [AOSUtilities retrieveOTPHeadersForDSID:@"-1"];
        id two = [AOSUtilities retrieveOTPHeadersForDSID:@"-2"];
        
        NSLog(@"%@", one);
        NSLog(@"%@", two);
    }
    return 0;
}
