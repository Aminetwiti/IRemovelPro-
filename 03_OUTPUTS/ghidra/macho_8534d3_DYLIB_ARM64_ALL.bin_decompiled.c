/* Decompiled from: macho_8534d3_DYLIB_ARM64_ALL.bin */

/* _validPublic @ 00005e74 */

undefined8 _validPublic(void)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 local_48;
  undefined auStack_40 [8];
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_0000c028;
  local_38 = *(undefined8 *)PTR__kSecAttrKeyType_0000c040;
  local_28 = *(undefined8 *)PTR__kSecAttrKeyTypeRSA_0000c048;
  local_30 = *(undefined8 *)PTR__kSecAttrKeyClass_0000c030;
  local_20 = *(undefined8 *)PTR__kSecAttrKeyClassPublic_0000c038;
  _objc_msgSend(&_OBJC_CLASS___NSDictionary,"dictionaryWithObjects:forKeys:count:",&local_28,
                &local_38,2);
  local_48 = _objc_retainAutoreleasedReturnValue();
  uVar1 = _objc_alloc(&_OBJC_CLASS___NSData);
  uVar1 = _objc_msgSend(uVar1,"initWithBase64EncodedString:options:",_publicKey,0);
  uVar2 = _SecKeyCreateWithData(uVar1,local_48,auStack_40);
  _objc_release(uVar1);
  _objc_storeStrong(&local_48,0);
  if (*(long *)PTR____stack_chk_guard_0000c028 == local_18) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}



/* _hex @ 00005fd8 */

void _hex(undefined8 param_1)

{
  undefined8 uVar1;
  undefined8 uVar2;
  int local_34;
  undefined8 local_30;
  ulong local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  local_18 = 0;
  _objc_storeStrong(&local_18,param_1);
  uVar1 = _objc_retainAutorelease(local_18);
  local_20 = _objc_msgSend(uVar1,"bytes");
  local_28 = _objc_msgSend(local_18,"length");
  _objc_msgSend(&_OBJC_CLASS___NSMutableString,"stringWithCapacity:",local_28 << 1);
  local_30 = _objc_retainAutoreleasedReturnValue();
  for (local_34 = 0; uVar1 = local_30, (ulong)(long)local_34 < local_28; local_34 = local_34 + 1) {
    _objc_msgSend(&_OBJC_CLASS___NSString,"stringWithFormat:",&cf__02lx);
    uVar2 = _objc_retainAutoreleasedReturnValue();
    _objc_msgSend(uVar1,"appendString:",uVar2);
    _objc_release(uVar2);
  }
  _objc_msgSend(&_OBJC_CLASS___NSString,"stringWithString:",local_30);
  uVar1 = _objc_retainAutoreleasedReturnValue();
  _objc_storeStrong(&local_30);
  _objc_storeStrong(&local_18,0);
  _objc_autoreleaseReturnValue(uVar1);
  return;
}



/* _logger @ 00006164 */

void _logger(void)

{
  _os_log_create("com.panyolsoft.blackhound","Log");
  _objc_autoreleaseReturnValue();
  return;
}



/* _replace_SecKeyRawVerify @ 00006188 */

undefined8 _replace_SecKeyRawVerify(void)

{
  return 0;
}



/* _replace_SecTrustEvaluateWithError @ 000061b4 */

undefined8 _replace_SecTrustEvaluateWithError(void)

{
  return 1;
}



/* _replace_SecKeyVerifySignature @ 000061d8 */

undefined8 _replace_SecKeyVerifySignature(void)

{
  return 1;
}



/* __logosLocalCtor_7d5e59f6 @ 00006208 */

void __logosLocalCtor_7d5e59f6(undefined4 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined uVar1;
  undefined8 uVar2;
  ulong uVar3;
  undefined auStack_40 [7];
  undefined local_39;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_14;
  
  local_28 = param_3;
  local_20 = param_2;
  local_14 = param_1;
  _MSHookFunction(PTR__SecKeyRawVerify_0000c008,_replace_SecKeyRawVerify,&_orig_SecKeyRawVerify);
  _MSHookFunction(PTR__SecTrustEvaluateWithError_0000c018,_replace_SecTrustEvaluateWithError,
                  &_orig_SecTrustEvaluateWithError);
  _MSHookFunction(PTR__SecKeyVerifySignature_0000c010,_replace_SecKeyVerifySignature,
                  &_orig_SecKeyVerifySignature);
  local_30 = _objc_getClass("MobileActivationDaemon");
  _MSHookMessageEx(local_30,"validateActivationDataSignature:activationSignature:withError:",
                   __logos_method__ungrouped_MobileActivationDaemon_validateActivationDataSignature_activationSignature_withError_
                   ,&
                    __logos_orig__ungrouped_MobileActivationDaemon_validateActivationDataSignature_activationSignature_withError_
                  );
  _MSHookMessageEx(local_30,"handleActivationInfo:withCompletionBlock:",
                   __logos_method__ungrouped_MobileActivationDaemon_handleActivationInfo_withCompletionBlock_
                   ,&
                    __logos_orig__ungrouped_MobileActivationDaemon_handleActivationInfo_withCompletionBlock_
                  );
  _logger();
  local_38 = _objc_retainAutoreleasedReturnValue();
  local_39 = 0;
  uVar3 = _os_log_type_enabled(local_38,0);
  uVar2 = local_38;
  uVar1 = local_39;
  if ((uVar3 & 1) != 0) {
    ___os_log_helper_16_0_0(auStack_40);
    __os_log_impl(0,uVar2,uVar1,0x8000,auStack_40,2);
  }
  _objc_storeStrong(&local_38,0);
  return;
}



/* __logos_method$_ungrouped$MobileActivationDaemon$validateActivationDataSignature$activationSignature$withError$ @ 00006394 */

undefined8
__logos_method__ungrouped_MobileActivationDaemon_validateActivationDataSignature_activationSignature_withError_
          (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  local_28 = 0;
  local_20 = param_2;
  local_18 = param_1;
  _objc_storeStrong(&local_28,param_3);
  local_30 = 0;
  _objc_storeStrong(&local_30,param_4);
  _objc_storeStrong(&local_30,0);
  _objc_storeStrong(&local_28,0);
  return 1;
}



/* __logos_method$_ungrouped$MobileActivationDaemon$handleActivationInfo$withCompletionBlock$ @ 00006414 */

/* WARNING: Removing unreachable block (ram,0x00007314) */
/* WARNING: Removing unreachable block (ram,0x00007414) */

void __logos_method__ungrouped_MobileActivationDaemon_handleActivationInfo_withCompletionBlock_
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined uVar1;
  char cVar2;
  uint uVar3;
  undefined8 uVar4;
  ulong uVar5;
  long lVar6;
  void *key;
  void *iv;
  void *dataIn;
  size_t sVar7;
  void *dataOut;
  size_t dataOutAvailable;
  undefined8 uVar8;
  undefined8 uVar9;
  char *data;
  undefined8 uVar10;
  undefined8 local_1a8;
  undefined8 local_1a0;
  undefined8 local_198;
  undefined8 local_190;
  undefined8 local_188;
  undefined8 local_180;
  undefined8 local_178;
  int local_16c;
  undefined8 local_168;
  char *local_160;
  undefined8 local_158;
  long local_150;
  undefined8 local_148;
  undefined8 local_140;
  undefined8 local_138;
  undefined8 local_130;
  undefined8 local_128;
  undefined8 local_120;
  undefined8 local_118;
  undefined8 local_110;
  undefined8 local_108;
  size_t local_100;
  CCCryptorStatus local_f4;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined auStack_b0 [3];
  undefined local_ad;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  cfstringStruct *local_58;
  undefined8 local_50;
  uchar auStack_48 [32];
  long local_28;
  
  local_28 = *(long *)PTR____stack_chk_guard_0000c028;
  local_90 = 0;
  local_88 = param_2;
  local_80 = param_1;
  _objc_storeStrong(&local_90,param_3);
  local_98 = 0;
  _objc_storeStrong(&local_98,param_4);
  uVar4 = _logger();
  local_a0 = _objc_retainAutoreleasedReturnValue(uVar4);
  local_ad = 0;
  uVar5 = _os_log_type_enabled(local_a0,0);
  uVar4 = local_a0;
  uVar1 = local_ad;
  if ((uVar5 & 1) != 0) {
    ___os_log_helper_16_0_0(auStack_b0);
    __os_log_impl(0,uVar4,uVar1,"starting magic",auStack_b0,2);
  }
  _objc_storeStrong(&local_a0,0);
  uVar4 = _objc_msgSend(local_90,"objectForKeyedSubscript:",&cf_ActivationRecord);
  local_b8 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = _objc_msgSend(local_b8,"objectForKeyedSubscript:",&cf_iRemovalRecord);
  local_c0 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = _objc_alloc(&_OBJC_CLASS___NSData);
  local_c8 = _objc_msgSend(uVar4,"initWithBase64EncodedString:options:",
                           &cf_FTY3ZTAvSjk3UjMwMjcyNDU4NjfxOTg9,0);
  uVar4 = _objc_alloc(&_OBJC_CLASS___NSData);
  local_d0 = _objc_msgSend(uVar4,"initWithBase64EncodedString:options:",&cf_MlAeNDgwMzU2Njc3,0);
  local_d8 = _objc_retain(&cf_anplN2VnNDVzZXI1Nmc0QMOja2pmaGV6anVnYmVodQ__);
  if (__logos_static_class_lookup_GestaltHlpr__klass == 0) {
    __logos_static_class_lookup_GestaltHlpr__klass = _objc_getClass("GestaltHlpr");
  }
  uVar4 = _objc_retainAutoreleaseReturnValue(__logos_static_class_lookup_GestaltHlpr__klass);
  uVar4 = _objc_msgSend(uVar4,"getSharedInstance");
  local_e0 = _objc_retainAutoreleasedReturnValue(uVar4);
  local_e8 = _objc_alloc(&_OBJC_CLASS___NSMutableDictionary);
  local_f0 = _objc_retain(local_c0);
  local_100 = 0;
  lVar6 = _objc_msgSend(local_f0,"length");
  uVar4 = _objc_msgSend(&_OBJC_CLASS___NSMutableData,"dataWithLength:",lVar6 + 0x10);
  local_108 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = _objc_retainAutorelease(local_c8);
  key = (void *)_objc_msgSend(uVar4,"bytes");
  uVar4 = _objc_retainAutorelease(local_d0);
  iv = (void *)_objc_msgSend(uVar4,"bytes");
  uVar4 = _objc_retainAutorelease(local_f0);
  dataIn = (void *)_objc_msgSend(uVar4,"bytes");
  sVar7 = _objc_msgSend(local_f0,"length");
  uVar4 = _objc_retainAutorelease(local_108);
  dataOut = (void *)_objc_msgSend(uVar4,"mutableBytes");
  dataOutAvailable = _objc_msgSend(local_108,"length");
  local_f4 = _CCCrypt(1,0,3,key,0x10,iv,dataIn,sVar7,dataOut,dataOutAvailable,&local_100);
  if (local_f4 != 0) {
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  _objc_msgSend(local_108,"setLength:",local_100);
  uVar4 = _objc_retainAutorelease(local_108);
  uVar4 = _objc_msgSend(uVar4,"mutableBytes");
  uVar4 = _objc_msgSend(&_OBJC_CLASS___NSData,"dataWithBytes:length:",uVar4,local_100);
  local_110 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = _objc_msgSend(&_OBJC_CLASS___NSPropertyListSerialization,
                        "propertyListWithData:options:format:error:",local_110,2,0,0);
  uVar8 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = local_e8;
  local_e8 = uVar8;
  _objc_release(uVar4);
  _objc_storeStrong(&local_110,0);
  local_118 = _objc_retain(&cf_iRemovalSignature);
  local_120 = _objc_retain(&
                           cf_o72tmOHQesn8Py9B78dsOy5oG0TxBVRI_d769rDsYnjVH93tp2NRPP_rTe8Ze9p0hvEpJCjsLezHML5ACDFkwAn2XF80aMAAaBS0M4B_ztF2aSbz6r_VD_VHNxArazs_HmxDGkdmQHbIKOy4X25uQsInV6LktpVzgz4Z_xj4xOA_
                          );
  uVar4 = _objc_msgSend(local_120,"dataUsingEncoding:",1);
  uVar4 = _objc_retainAutoreleasedReturnValue(uVar4);
  local_78 = 0;
  _objc_storeStrong(&local_78,uVar4);
  uVar8 = _objc_retain(local_78);
  _objc_storeStrong(&local_78,0);
  _objc_release(uVar4);
  local_130 = uVar8;
  uVar4 = _objc_msgSend(local_118,"dataUsingEncoding:",1);
  uVar4 = _objc_retainAutoreleasedReturnValue(uVar4);
  local_70 = 0;
  _objc_storeStrong(&local_70,uVar4);
  uVar8 = _objc_retain(local_70);
  _objc_storeStrong(&local_70,0);
  _objc_release(uVar4);
  local_138 = uVar8;
  uVar4 = _validPublic();
  cVar2 = _SecKeyVerifySignature
                    (uVar4,*(undefined8 *)PTR__kSecKeyAlgorithmRSASignatureRaw_0000c050,local_138,
                     local_130,local_128);
  if (cVar2 == '\0') {
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  uVar4 = _objc_msgSend(local_e8,"objectForKeyedSubscript:",&cf_activation_record);
  lVar6 = _objc_retainAutoreleasedReturnValue(uVar4);
  _objc_release();
  if (lVar6 == 0) {
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  uVar4 = _objc_msgSend(local_e8,"objectForKeyedSubscript:",&cf_activation_record);
  uVar8 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = local_e8;
  local_e8 = uVar8;
  _objc_release(uVar4);
  uVar4 = _objc_msgSend(local_e8,"objectForKey:",local_118);
  uVar4 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar8 = _objc_msgSend(&_OBJC_CLASS___NSPropertyListSerialization,
                        "propertyListWithData:options:format:error:",uVar4,2,0,0);
  local_140 = _objc_retainAutoreleasedReturnValue(uVar8);
  _objc_release(uVar4);
  uVar4 = _objc_msgSend(local_140,"objectForKeyedSubscript:",&cf_irs);
  local_148 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = _objc_msgSend(local_140,"objectForKeyedSubscript:",&cf_irh);
  local_150 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = _objc_msgSend(local_e0,"copyAnswer:",&cf_SerialNumber);
  uVar8 = _objc_msgSend(local_e0,"copyAnswer:",&cf_UniqueDeviceID);
  uVar9 = _objc_msgSend(&_OBJC_CLASS___NSString,"stringWithFormat:",&cf_________);
  local_158 = _objc_retainAutoreleasedReturnValue(uVar9);
  _objc_release(uVar8);
  _objc_release(uVar4);
  uVar4 = _objc_retainAutorelease(local_158);
  data = (char *)_objc_msgSend(uVar4,"UTF8String");
  local_160 = data;
  sVar7 = _strlen(data);
  _CC_SHA256(data,(CC_LONG)sVar7,auStack_48);
  uVar4 = _objc_msgSend(&_OBJC_CLASS___NSMutableString,"stringWithCapacity:",0x40);
  local_168 = _objc_retainAutoreleasedReturnValue(uVar4);
  for (local_16c = 0; local_16c < 0x20; local_16c = local_16c + 1) {
    _objc_msgSend(local_168,"appendFormat:",&cf__02x);
  }
  local_178 = _objc_retain(local_168);
  uVar4 = _objc_msgSend(local_158,"dataUsingEncoding:",1);
  uVar4 = _objc_retainAutoreleasedReturnValue(uVar4);
  local_68 = 0;
  _objc_storeStrong(&local_68,uVar4);
  uVar8 = _objc_retain(local_68);
  _objc_storeStrong(&local_68,0);
  _objc_release(uVar4);
  local_180 = uVar8;
  uVar8 = _validPublic();
  uVar4 = local_180;
  uVar10 = *(undefined8 *)PTR__kSecKeyAlgorithmRSASignatureRaw_0000c050;
  local_60 = 0;
  _objc_storeStrong(&local_60,local_148);
  uVar9 = _objc_retain(local_60);
  _objc_storeStrong(&local_60,0);
  cVar2 = _SecKeyVerifySignature(uVar8,uVar10,uVar4,uVar9,local_188);
  uVar4 = local_178;
  if (cVar2 == '\0') {
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  local_190 = 0;
  uVar8 = _hex(local_150);
  uVar8 = _objc_retainAutoreleasedReturnValue(uVar8);
  uVar3 = _objc_msgSend(uVar4,"isEqualToString:",uVar8);
  _objc_release(uVar8);
  if ((uVar3 & 1) == 0) {
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  local_198 = _objc_alloc(&_OBJC_CLASS___NSMutableDictionary);
  local_58 = &cf_ActivationRecord;
  local_50 = local_e8;
  uVar4 = _objc_msgSend(&_OBJC_CLASS___NSDictionary,"dictionaryWithObjects:forKeys:count:",&local_50
                        ,&local_58,1);
  uVar8 = _objc_retainAutoreleasedReturnValue(uVar4);
  uVar4 = local_198;
  local_198 = uVar8;
  _objc_release(uVar4);
  uVar4 = _objc_msgSend(local_198,"objectForKeyedSubscript:",&cf_ActivationRecord);
  uVar4 = _objc_retainAutoreleasedReturnValue(uVar4);
  _objc_msgSend(uVar4,"removeObjectForKey:",&cf_iRemovalSignature);
  _objc_release(uVar4);
  local_1a8 = 0;
  uVar4 = _objc_msgSend(&_OBJC_CLASS___NSPropertyListSerialization,
                        "dataWithPropertyList:format:options:error:",local_198,200,0,&local_1a8);
  uVar4 = _objc_retainAutoreleasedReturnValue(uVar4);
  _objc_storeStrong(&local_190,local_1a8);
  local_1a0 = uVar4;
  _objc_msgSend(local_80,"handleActivationInfoWithSession:activationSignature:completionBlock:",
                uVar4,&cf_1234567890123456,local_98);
  _objc_storeStrong(&local_1a0,0);
  _objc_storeStrong(&local_198,0);
  _objc_storeStrong(&local_190);
  _objc_storeStrong(&local_178,0);
  _objc_storeStrong(&local_168,0);
  _objc_storeStrong(&local_158,0);
  _objc_storeStrong(&local_150,0);
  _objc_storeStrong(&local_148,0);
  _objc_storeStrong(&local_140,0);
  _objc_storeStrong(&local_120,0);
  _objc_storeStrong(&local_118,0);
  _objc_storeStrong(&local_108,0);
  _objc_storeStrong(&local_f0,0);
  _objc_storeStrong(&local_e8,0);
  _objc_storeStrong(&local_e0,0);
  _objc_storeStrong(&local_d8,0);
  _objc_storeStrong(&local_d0,0);
  _objc_storeStrong(&local_c8,0);
  _objc_storeStrong(&local_c0,0);
  _objc_storeStrong(&local_b8,0);
  _objc_storeStrong(&local_98);
  _objc_storeStrong(&local_90,0);
  if (*(long *)PTR____stack_chk_guard_0000c028 != local_28) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return;
}



/* ___os_log_helper_16_0_0 @ 000074ac */

void ___os_log_helper_16_0_0(undefined *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  return;
}



