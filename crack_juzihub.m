// crack_juzihub.m
// 还原 KamiGate.dylib 破解手法 (Ghidra 反编译确认: 154函数, 远程卡密验证)
//
// 编译命令 (GitHub Actions macos-latest):
// xcrun clang -target arm64-apple-ios15.0 \
//   -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
//   -dynamiclib -fobjc-arc \
//   -framework UIKit -framework Foundation -framework CoreGraphics \
//   -framework Security -framework CommonCrypto \
//   -o crack_juzihub.dylib crack_juzihub.m
//
// KamiGate 攻击链 (Ghidra 确认):
//   1. Constructor 延迟 0.25 秒执行主逻辑
//   2. 检查 Keychain (kg.card.v1) 是否有已保存卡密
//   3. 无卡密 -> UIAlertController 弹窗输入
//   4. 远程卡密验证:
//      - 请求体: v2|<card>|<device>|<model>|<timestamp>|<timestamp>
//      - HMAC-SHA256 签名 (X-Sign2 头)
//      - 3秒频率限制
//      - 响应: ok|CARD_ON (成功) / invalid_card / expired / too_frequent
//   5. 验证成功 -> 保存 Keychain -> dlopen 加载 JuziHub(18).dylib
//   6. 同时加载 ClaudeV13Skin.dylib + LightningSkin.dylib (皮肤)
//   7. Ra_x1nY_Install 安装悬浮球 (CK_R_aX1ny_FloatBall)
//   8. NSSelectorFromString 动态调用 JuziHub 解锁方法
//   9. sysctl 反调试检测 (可选)

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/sysctl.h>

#pragma mark - ============ 全局状态 ============

static NSString *const kKamiGateCardKey = @"kg.card.v1";
static NSString *const kKamiGateSessionKey = @"kg.session.v2";
static NSString *const kTargetDylibName = @"JuziHub(18).dylib";
static NSString *const kSkinDylib1 = @"ClaudeV13Skin.dylib";
static NSString *const kSkinDylib2 = @"LightningSkin.dylib";
static NSString *const kFloatBallClass = @"CK_R_aX1ny_FloatBall";
static NSString *const kInstallSelector = @"Ra_x1nY_Install";

// 频率限制 (Ghidra: 3秒)
static NSTimeInterval gLastRequestTime = 0;
static const NSTimeInterval kRequestInterval = 3.0;

// HMAC 签名密钥 (KamiGate 内置, 需要从二进制提取)
static NSString *const kHMACKey = @"KamiGate_Sign_Key_v2";

#pragma mark - ============ Keychain 存储 (Ghidra 确认: kg.card.v1 / kg.session.v2) ============

static NSData *KamiGateKeychainQuery(NSString *key) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: key,
        (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFDataRef data = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&data);
    if (status == errSecSuccess && data) {
        NSData *result = (__bridge_transfer NSData *)data;
        return result;
    }
    return nil;
}

static BOOL KamiGateKeychainSet(NSString *key, NSData *data) {
    // 先删后加
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: key,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);

    NSDictionary *addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: key,
        (__bridge id)kSecValueData: data,
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    return status == errSecSuccess;
}

static NSString *KamiGateLoadCard(void) {
    NSData *data = KamiGateKeychainQuery(kKamiGateCardKey);
    if (data) {
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}

static void KamiGateSaveCard(NSString *card) {
    NSData *data = [card dataUsingEncoding:NSUTF8StringEncoding];
    KamiGateKeychainSet(kKamiGateCardKey, data);
}

#pragma mark - ============ 设备信息 (Ghidra: device/model 字段) ============

static NSString *KamiGateDeviceID(void) {
    // Ghidra: LLDSUU1D (可能是 UDID 的混淆/编码)
    // 简化: 用 identifierForVendor
    UIDevice *device = [UIDevice currentDevice];
    NSString *uuid = device.identifierForVendor.UUIDString;
    // 去掉连字符, 大写 (模拟 LLDSUU1D 格式)
    return [[uuid stringByReplacingOccurrencesOfString:@"-" withString:@""] uppercaseString];
}

static NSString *KamiGateDeviceModel(void) {
    // 设备型号, 如 "iPhone14,3" / "iPad13,4"
    struct utsname systemInfo;
    uname(&systemInfo);
    return [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding] ?: @"unknown";
}

#pragma mark - ============ HMAC-SHA256 签名 (Ghidra: X-Sign2 头, CCHmac) ============

static NSString *KamiGateSign(NSString *body) {
    // Ghidra: X-Sign2 头, 用 CCHmac 做 HMAC-SHA256
    const char *keyCString = [kHMACKey cStringUsingEncoding:NSUTF8StringEncoding];
    const char *dataCString = [body cStringUsingEncoding:NSUTF8StringEncoding];

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyCString, strlen(keyCString),
           dataCString, strlen(dataCString), digest);

    // 转为 hex 字符串
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return hex;
}

#pragma mark - ============ 远程卡密验证 (Ghidra: FUN_000068e8, 2580字节) ============

typedef NS_ENUM(NSInteger, KamiGateVerifyResult) {
    KamiGateVerifySuccess = 0,
    KamiGateVerifyInvalidCard = 1,
    KamiGateVerifyExpired = 2,
    KamiGateVerifyTooFrequent = 3,
    KamiGateVerifyNetworkError = 4,
};

static KamiGateVerifyResult KamiGateVerifyCard(NSString *card, NSString **errorMessage) {
    // Ghidra: FUN_000068e8 (2580字节, 最大函数)
    // 反编译确认:
    //   1. 检查频率限制 (3秒)
    //   2. URL 编码卡密
    //   3. 获取设备信息 (device/model)
    //   4. 构造请求体: v2|<card>|<device>|<model>|<timestamp>|<timestamp>
    //   5. HMAC-SHA256 签名 (X-Sign2 头)
    //   6. 发送请求
    //   7. 解析响应: ok|CARD_ON / invalid_card / expired / too_frequent

    // 1. 频率限制 (Ghidra: 3秒)
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - gLastRequestTime < kRequestInterval) {
        if (errorMessage) *errorMessage = @"too_frequent";
        return KamiGateVerifyTooFrequent;
    }
    gLastRequestTime = now;

    // 2. URL 编码卡密
    NSString *encodedCard = [card stringByAddingPercentEncodingWithAllowedCharacters:
                              [NSCharacterSet URLQueryAllowedCharacterSet]];

    // 3. 获取设备信息
    NSString *deviceID = KamiGateDeviceID();
    NSString *deviceModel = KamiGateDeviceModel();

    // 4. 构造请求体: v2|<card>|<device>|<model>|<timestamp>|<timestamp>
    // Ghidra 字符串: v2|%@|%@|%@|%.0f|%.0f
    NSString *body = [NSString stringWithFormat:@"v2|%@|%@|%@|%.0f|%.0f",
                       encodedCard, deviceID, deviceModel, now, now];

    // 5. HMAC-SHA256 签名
    NSString *signature = KamiGateSign(body);

    // 6. 发送请求 (Ghidra: FUN_00009094, 1860字节)
    // 注意: 实际 KamiGate 的服务器 URL 需要从二进制提取, 这里用占位
    NSURL *url = [NSURL URLWithString:@"https://kamigate.example.com/api/verify"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    [request setValue:signature forHTTPHeaderField:@"X-Sign2"];
    [request setValue:@"no-cache, no-store" forHTTPHeaderField:@"Cache-Control"];
    [request setValue:@"no-cache" forHTTPHeaderField:@"Pragma"];

    // 同步发送 (Ghidra: 用 dispatch_semaphore 同步等待)
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSData *responseData = nil;
    __block NSError *requestError = nil;

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            responseData = data;
            requestError = error;
            dispatch_semaphore_signal(semaphore);
        }];
    [task resume];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (requestError || !responseData) {
        if (errorMessage) *errorMessage = @"network_error";
        return KamiGateVerifyNetworkError;
    }

    // 7. 解析响应 (Ghidra: FUN_000089fc, 1308字节)
    NSString *response = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
    NSLog(@"[KamiGate] verify response: %@", response);

    // 检查是否以 "ok|" 开头 (Ghidra: hasPrefix:@"ok|")
    if ([response hasPrefix:@"ok|"]) {
        // 验证成功, 响应格式: ok|CARD_ON
        if (errorMessage) *errorMessage = nil;
        return KamiGateVerifySuccess;
    }

    // 检查错误类型
    if ([response containsString:@"invalid_card"]) {
        if (errorMessage) *errorMessage = @"invalid_card";
        return KamiGateVerifyInvalidCard;
    }
    if ([response containsString:@"expired"]) {
        if (errorMessage) *errorMessage = @"expired";
        return KamiGateVerifyExpired;
    }
    if ([response containsString:@"too_frequent"]) {
        if (errorMessage) *errorMessage = @"too_frequent";
        return KamiGateVerifyTooFrequent;
    }

    if (errorMessage) *errorMessage = response ?: @"unknown_error";
    return KamiGateVerifyNetworkError;
}

#pragma mark - ============ 卡密弹窗 (Ghidra: UIAlertController + addTextField) ============

static void KamiGateShowPrompt(void) {
    // Ghidra: UIAlertController + addTextFieldWithConfigurationHandler:
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"KamiGate"
                                                                         message:@"请输入卡密"
                                                                  preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
            textField.placeholder = @"卡密";
            textField.secureTextEntry = YES;
        }];

        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            NSString *input = alert.textFields.firstObject.text ?: @"";
            if (input.length == 0) return;

            // 后台线程验证 (避免阻塞 UI)
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                NSString *errorMsg = nil;
                KamiGateVerifyResult result = KamiGateVerifyCard(input, &errorMsg);

                dispatch_async(dispatch_get_main_queue(), ^{
                    if (result == KamiGateVerifySuccess) {
                        NSLog(@"[KamiGate] 卡密验证通过");
                        KamiGateSaveCard(input);
                        KamiGateOnVerified();
                    } else {
                        // 显示 error (与用户描述的"现在输入显示error"一致)
                        NSString *msg = @"卡密无效或已过期";
                        if (errorMsg) {
                            if ([errorMsg isEqualToString:@"invalid_card"]) msg = @"无效卡密";
                            else if ([errorMsg isEqualToString:@"expired"]) msg = @"卡密已过期";
                            else if ([errorMsg isEqualToString:@"too_frequent"]) msg = @"请求太频繁, 请稍后再试";
                            else if ([errorMsg isEqualToString:@"network_error"]) msg = @"网络错误";
                        }
                        UIAlertController *errorAlert = [UIAlertController alertControllerWithTitle:@"Error"
                                                                                               message:msg
                                                                                        preferredStyle:UIAlertControllerStyleAlert];
                        [errorAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                        [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:errorAlert animated:YES completion:nil];
                    }
                });
            });
        }]];

        [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];

        [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

#pragma mark - ============ 验证成功后处理 (dlopen + 皮肤 + 悬浮球 + 解锁) ============

static void KamiGateOnVerified(void) {
    // Ghidra: 验证成功后
    //   1. dlopen 加载 JuziHub(18).dylib
    //   2. 同时加载 ClaudeV13Skin.dylib + LightningSkin.dylib
    //   3. Ra_x1nY_Install 安装悬浮球
    //   4. NSSelectorFromString 动态调用解锁方法

    // 1. dlopen 加载目标 dylib
    NSString *dylibPath = [[NSBundle mainBundle] pathForResource:@"JuziHub(18)" ofType:@"dylib"];
    if (!dylibPath) {
        // 尝试从 Frameworks 目录
        dylibPath = [[NSBundle mainBundle].privateFrameworksPath stringByAppendingPathComponent:kTargetDylibName];
    }
    if (dylibPath && [[NSFileManager defaultManager] fileExistsAtPath:dylibPath]) {
        void *handle = dlopen([dylibPath UTF8String], RTLD_NOW);
        if (handle) {
            NSLog(@"[KamiGate] dlopen loaded: %@", kTargetDylibName);
        } else {
            NSLog(@"[KamiGate] dlopen failed: %s", dlerror());
        }
    }

    // 2. 加载皮肤 dylib (Ghidra 字符串: ClaudeV13Skin.dylib, LightningSkin.dylib)
    NSArray *skinDylibs = @[kSkinDylib1, kSkinDylib2];
    for (NSString *skinName in skinDylibs) {
        NSString *skinPath = [[NSBundle mainBundle] pathForResource:skinName.stringByDeletingPathExtension ofType:@"dylib"];
        if (skinPath && [[NSFileManager defaultManager] fileExistsAtPath:skinPath]) {
            dlopen([skinPath UTF8String], RTLD_NOW);
            NSLog(@"[KamiGate] skin loaded: %@", skinName);
        }
    }

    // 3. 安装悬浮球 (Ghidra: CK_R_aX1ny_FloatBall, Ra_x1nY_Install)
    Class floatBallClass = NSClassFromString(kFloatBallClass);
    if (floatBallClass) {
        SEL installSel = NSSelectorFromString(kInstallSelector);
        if ([floatBallClass respondsToSelector:installSel]) {
            ((void(*)(id, SEL))objc_msgSend)(floatBallClass, installSel);
            NSLog(@"[KamiGate] float ball installed");
        }
    }

    // 4. 动态调用 JuziHub 解锁方法
    KamiGateUnlockJuziHub();

    // 5. 注入 MenuUnlockKey/MenuUnlockExpireTS (JuziHub(18) 验证系统核心)
    KamiGateInjectMenuUnlock();

    // 6. 伪造 UDID + 抑制 UDID 弹窗 (JuziHub(18) 字符串确认: fakeUDID/suppressed UDID alert)
    KamiGateFakeUDID();
    KamiGateSuppressUDIDAlert();

    NSLog(@"[KamiGate] KamiGateOnVerified: all done");
}

#pragma mark - ============ 动态调用 JuziHub 解锁方法 (NSSelectorFromString) ============

static void KamiGateUnlockJuziHub(void) {
    // Ghidra: 用 NSClassFromString + NSSelectorFromString 动态调用
    // JuziHub 有完整加密体系 (AES-256 + HMAC-SHA256), 但验证通过后直接调用内部解锁方法

    NSArray *juziClasses = @[
        @"JuziHub", @"JuziManager", @"JuziVerify", @"JuziAuth",
        @"JuziLicense", @"JuziActivation", @"HubManager", @"HubVerify",
    ];

    for (NSString *className in juziClasses) {
        Class cls = NSClassFromString(className);
        if (!cls) continue;
        NSLog(@"[KamiGate] found JuziHub class: %@", className);

        // 获取单例
        id instance = nil;
        NSArray *singletonSels = @[@"sharedManager", @"sharedInstance", @"defaultManager", @"manager", @"sharedHub"];
        for (NSString *selName in singletonSels) {
            SEL sel = NSSelectorFromString(selName);
            if ([cls respondsToSelector:sel]) {
                instance = ((id(*)(id, SEL))objc_msgSend)(cls, sel);
                break;
            }
        }
        if (!instance) continue;

        // 调用解锁方法
        NSArray *unlockSelectors = @[
            @"unlock", @"activate", @"verifySuccess", @"setVerified:",
            @"setLicensed:", @"setAuthorized:", @"setActivated:",
        ];
        for (NSString *selName in unlockSelectors) {
            SEL sel = NSSelectorFromString(selName);
            if ([instance respondsToSelector:sel]) {
                if ([selName hasSuffix:@":"]) {
                    ((void(*)(id, SEL, BOOL))objc_msgSend)(instance, sel, YES);
                } else {
                    ((void(*)(id, SEL))objc_msgSend)(instance, sel);
                }
                NSLog(@"[KamiGate] called unlock: %@ on %@", selName, className);
            }
        }

        // 设置到期时间为 2099
        NSArray *expireSels = @[@"setExpireDate:", @"setExpirationDate:", @"setExpireTime:"];
        NSDate *farFuture = [NSDate dateWithTimeIntervalSinceNow:60*60*24*365*73];
        for (NSString *selName in expireSels) {
            SEL sel = NSSelectorFromString(selName);
            if ([instance respondsToSelector:sel]) {
                ((void(*)(id, SEL, id))objc_msgSend)(instance, sel, farFuture);
            }
        }
    }
}

#pragma mark - ============ 注入 MenuUnlockKey/MenuUnlockExpireTS (JuziHub(18) 验证核心) ============

static void KamiGateInjectMenuUnlock(void) {
    // JuziHub(18).dylib 字符串确认:
    //   "MenuUnlockKey" / "MenuUnlockExpireTS"
    //   "dict fields=%lu, has MenuUnlockKey=%d has MenuUnlockExpireTS=%d"
    //   "Apply FAIL: expireTS invalid ts=%llu now=%llu diff=%lld"
    //   "backend REJECTED (verify/decrypt/bounds)"
    // 验证系统通过 NSDictionary 传递 MenuUnlockKey + MenuUnlockExpireTS
    // 破解者需要构造这个字典并注入到 LocalDataManager / RLManager

    // 构造 MenuUnlockKey (从远程验证响应中获取, 这里用硬编码示例)
    // 真实卡密验证成功后, 服务器返回的 key 会被加密存储
    NSString *menuUnlockKey = @"KAMI_GATE_UNLOCK_KEY_v2";
    uint64_t expireTS = (uint64_t)([[NSDate date] timeIntervalSince1970] + 315360000.0); // 10年后

    NSDictionary *unlockDict = @{
        @"MenuUnlockKey": menuUnlockKey,
        @"MenuUnlockExpireTS": @(expireTS),
    };
    NSLog(@"[KamiGate] InjectMenuUnlock: key=%@ expire=%llu", menuUnlockKey, expireTS);

    // 尝试注入到 LocalDataManager (JuziHub(18) 类名确认)
    Class localDataCls = NSClassFromString(@"LocalDataManager");
    if (localDataCls) {
        id localData = nil;
        NSArray *singletonSels = @[@"sharedManager", @"sharedInstance", @"defaultManager", @"manager"];
        for (NSString *selName in singletonSels) {
            SEL sel = NSSelectorFromString(selName);
            if ([localDataCls respondsToSelector:sel]) {
                localData = ((id(*)(id, SEL))objc_msgSend)(localDataCls, sel);
                break;
            }
        }
        if (localData) {
            // 尝试设置 unlock dict
            NSArray *setSels = @[@"setMenuUnlockDict:", @"setUnlockDict:", @"applyUnlockDict:", @"setLicenseDict:"];
            for (NSString *selName in setSels) {
                SEL sel = NSSelectorFromString(selName);
                if ([localData respondsToSelector:sel]) {
                    ((void(*)(id, SEL, id))objc_msgSend)(localData, sel, unlockDict);
                    NSLog(@"[KamiGate] injected unlock dict via LocalDataManager.%@", selName);
                }
            }
        }
    }

    // 尝试注入到 RLManager (可能是 Remote License Manager)
    Class rlCls = NSClassFromString(@"RLManager");
    if (rlCls) {
        id rlMgr = nil;
        NSArray *singletonSels = @[@"sharedManager", @"sharedInstance", @"defaultManager", @"manager"];
        for (NSString *selName in singletonSels) {
            SEL sel = NSSelectorFromString(selName);
            if ([rlCls respondsToSelector:sel]) {
                rlMgr = ((id(*)(id, SEL))objc_msgSend)(rlCls, sel);
                break;
            }
        }
        if (rlMgr) {
            NSArray *setSels = @[@"setUnlockInfo:", @"setLicenseInfo:", @"applyLicense:", @"setVerified:"];
            for (NSString *selName in setSels) {
                SEL sel = NSSelectorFromString(selName);
                if ([rlMgr respondsToSelector:sel]) {
                    if ([selName hasSuffix:@":"]) {
                        ((void(*)(id, SEL, id))objc_msgSend)(rlMgr, sel, unlockDict);
                    } else {
                        ((void(*)(id, SEL))objc_msgSend)(rlMgr, sel);
                    }
                    NSLog(@"[KamiGate] injected via RLManager.%@", selName);
                }
            }
        }
    }

    // 通过 NSUserDefaults 注入 (JuziHub 可能用 NSUserDefaults 存储)
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:menuUnlockKey forKey:@"MenuUnlockKey"];
    [defaults setObject:@(expireTS) forKey:@"MenuUnlockExpireTS"];
    [defaults synchronize];
    NSLog(@"[KamiGate] injected MenuUnlockKey/ExpireTS to NSUserDefaults");
}

#pragma mark - ============ 伪造 UDID (JuziHub(18) 字符串确认: fakeUDID) ============

static void KamiGateFakeUDID(void) {
    // JuziHub(18).dylib 字符串确认:
    //   "fakeUDID = %@"
    //   "getudid" / "getdevice" / "UDID"
    //   "reUDID"
    //   "suppressed profile/UDID alert while locked"
    // JuziHub 用 UDID 绑定设备, 破解者需要伪造 UDID 绕过设备绑定

    // 生成一个固定的伪造 UDID (格式: 40位十六进制)
    NSString *fakeUDID = @"00008110-001A2D4C0E22801E"; // 示例, 真实破解者会用卡密绑定的 UDID
    NSLog(@"[KamiGate] FakeUDID: %@", fakeUDID);

    // Hook UIDevice uniqueIdentifier (已废弃但可能被调用)
    Class uiDeviceCls = [UIDevice class];
    SEL udidSel = NSSelectorFromString(@"uniqueIdentifier");
    Method udidMethod = class_getInstanceMethod(uiDeviceCls, udidSel);
    if (udidMethod) {
        IMP original = method_getImplementation(udidMethod);
        IMP fakeImp = imp_implementationWithBlock(^NSString *(id self) {
            return fakeUDID;
        });
        method_setImplementation(udidMethod, fakeImp);
        NSLog(@"[KamiGate] hooked UIDevice.uniqueIdentifier");
    }

    // Hook 可能的自定义 UDID 获取方法
    NSArray *udidClasses = @[@"LocalDataManager", @"RLManager", @"TBManager", @"VerConfig"];
    NSArray *udidSels = @[@"getUDID", @"udid", @"deviceUDID", @"getDeviceUDID", @"currentUDID", @"deviceIdentifier"];

    for (NSString *className in udidClasses) {
        Class cls = NSClassFromString(className);
        if (!cls) continue;
        for (NSString *selName in udidSels) {
            SEL sel = NSSelectorFromString(selName);
            Method method = class_getInstanceMethod(cls, sel);
            if (!method) method = class_getClassMethod(cls, sel);
            if (method) {
                IMP fakeImp = imp_implementationWithBlock(^NSString *(id self) {
                    return fakeUDID;
                });
                method_setImplementation(method, fakeImp);
                NSLog(@"[KamiGate] hooked %@.%@ -> fakeUDID", className, selName);
            }
        }
    }

    // 通过 NSUserDefaults 设置 UDID
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:fakeUDID forKey:@"UDID"];
    [defaults setObject:fakeUDID forKey:@"fakeUDID"];
    [defaults setObject:fakeUDID forKey:@"deviceUDID"];
    [defaults synchronize];
}

#pragma mark - ============ 抑制 UDID 弹窗 (JuziHub(18) 字符串确认: suppressed UDID alert) ============

static void KamiGateSuppressUDIDAlert(void) {
    // JuziHub(18).dylib 字符串确认:
    //   "suppressed profile/UDID alert while locked"
    //   "suppressed profile/UDID openURL while locked: %@"
    // JuziHub 会弹出 UDID 相关的弹窗/配置描述文件, 破解者需要抑制

    // Hook UIAlertController show / present 来抑制 UDID 弹窗
    Class alertCls = [UIAlertController class];
    SEL viewDidAppearSel = @selector(viewDidAppear:);
    Method origMethod = class_getInstanceMethod(alertCls, viewDidAppearSel);
    if (origMethod) {
        IMP originalImp = method_getImplementation(origMethod);
        IMP suppressImp = imp_implementationWithBlock(^(id self, BOOL animated) {
            // 检查弹窗标题/内容是否包含 UDID 相关关键词
            NSString *title = @"";
            NSString *message = @"";
            @try {
                title = [self valueForKey:@"title"] ?: @"";
                message = [self valueForKey:@"message"] ?: @"";
            } @catch (NSException *e) {}

            NSArray *udidKeywords = @[@"UDID", @"udid", @"设备标识", @"描述文件", @"profile", @"Profile", @"安装描述"];
            for (NSString *kw in udidKeywords) {
                if ([title containsString:kw] || [message containsString:kw]) {
                    NSLog(@"[KamiGate] suppressed UDID alert: %@", title);
                    [self dismissViewControllerAnimated:NO completion:nil];
                    return;
                }
            }
            // 调用原始实现
            ((void(*)(id, SEL, BOOL))originalImp)(self, viewDidAppearSel, animated);
        });
        method_setImplementation(origMethod, suppressImp);
        NSLog(@"[KamiGate] hooked UIAlertController.viewDidAppear for UDID suppression");
    }

    // Hook UIApplication openURL 来抑制 UDID 配置描述文件打开
    Class appCls = [UIApplication class];
    SEL openURLSel = @selector(openURL:options:completionHandler:);
    Method openURLMethod = class_getInstanceMethod(appCls, openURLSel);
    if (openURLMethod) {
        IMP originalOpenURL = method_getImplementation(openURLMethod);
        IMP hookOpenURL = imp_implementationWithBlock(^(id self, NSURL *url, NSDictionary *options, void (^completion)(BOOL success)) {
            NSString *urlStr = [url absoluteString];
            if ([urlStr containsString:@"udid"] || [urlStr containsString:@"profile"] || [urlStr containsString:@"mobileconfig"]) {
                NSLog(@"[KamiGate] suppressed UDID openURL: %@", urlStr);
                if (completion) completion(NO);
                return;
            }
            ((void(*)(id, SEL, NSURL *, NSDictionary *, void(^)(BOOL)))originalOpenURL)(self, openURLSel, url, options, completion);
        });
        method_setImplementation(openURLMethod, hookOpenURL);
        NSLog(@"[KamiGate] hooked UIApplication.openURL for UDID suppression");
    }
}

#pragma mark - ============ 反调试检测 (Ghidra: sysctl) ============

static BOOL KamiGateIsDebugged(void) {
    // Ghidra: 用 sysctl 检测调试器 (P_TRACED flag)
    // 注意: 这是破解者用来检测是否被反向分析, 不是目标 dylib 的反调试
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

#pragma mark - ============ Constructor (Ghidra: FUN_00004000, 128字节) ============

__attribute__((constructor))
static void KamiGate_Init(void) {
    // Ghidra: FUN_00004000 (128字节, entry/constructor)
    // 反编译确认:
    //   1. 调用 FUN_00004080 (初始化)
    //   2. 延迟 0.25 秒 (250000000 纳秒) 后在主线程执行主逻辑 block

    NSLog(@"[KamiGate] KamiGate_Init: loaded");

    // 反调试检测 (如果被调试, 可选退出)
    if (KamiGateIsDebugged()) {
        NSLog(@"[KamiGate] debugger detected");
        // 可选: exit(0);
    }

    // 延迟 0.25 秒后执行主逻辑 (Ghidra: dispatch_time(0, 250000000))
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250000000), dispatch_get_main_queue(), ^{
        NSLog(@"[KamiGate] main logic started (0.25s delay)");

        // 检查 Keychain 中是否有已保存的卡密
        NSString *savedCard = KamiGateLoadCard();
        if (savedCard) {
            NSLog(@"[KamiGate] found saved card, verifying...");
            // 有保存的卡密, 直接验证
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                NSString *errorMsg = nil;
                KamiGateVerifyResult result = KamiGateVerifyCard(savedCard, &errorMsg);
                if (result == KamiGateVerifySuccess) {
                    KamiGateOnVerified();
                } else {
                    // 保存的卡密失效, 重新弹窗
                    KamiGateShowPrompt();
                }
            });
        } else {
            // 无保存的卡密, 弹窗输入
            NSLog(@"[KamiGate] no saved card, showing prompt");
            KamiGateShowPrompt();
        }
    });
}
