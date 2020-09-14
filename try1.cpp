public class LicenseUtils {
 
    /**
     * DES加密秘钥，DES需要16位的字符加密，所以秘钥是8位，也可以自动补位
     */
    private static final String password = "aaaaaaaa";
 
    /**
     * 获取设备机器码：主要是将获取的硬件信息通过散列加密生成唯一的机器码
     *
     * @return
     */
    public static String getDeviceSN() {
        DES des = SecureUtil.des(password.getBytes());
        String cpuId = SerialNumberUtil.getCPUId();
        String biosSerial = SerialNumberUtil.getBiosSerial();
        List<String> diskSerial = SerialNumberUtil.getDiskSerial();
        List<String> mac = SerialNumberUtil.getMac();
        String str = cpuId + biosSerial + String.join("", diskSerial) + String.join("", mac);
        HMac hMac = new HMac(HmacAlgorithm.HmacMD5, des.getSecretKey());
        return hMac.digestHex(str);
    }
 
    /**
     * 获取公钥,公钥密码默认放在resource下面
     *
     * @return
     */
    public static String getPublicKey() throws IOException {
        ClassPathResource pathResource = new ClassPathResource("publicKey.txt");
        InputStream inputStream = pathResource.getInputStream();
        return new String(ByteStreams.toByteArray(inputStream));
    }
 
 
    /**
     * 解密，先使用DES做HEX解密以后，再使用公钥做非对称解密
     *
     * @param cipherText
     * @return
     * @throws IOException
     */
    public static String decrypt(String cipherText) {
        String s;
        try {
            DES des = SecureUtil.des(password.getBytes());
            RSA rsa = new RSA(null, getPublicKey());
            byte[] decryptHex = des.decrypt(cipherText);
            byte[] decrypt = rsa.decrypt(decryptHex, KeyType.PublicKey);
            s = new String(decrypt);
            log.info("decrypt res: " + s);
        } catch (Exception e) {
            log.error("decrypt error: " + e);
            s = "0";
        }
        return s;
    }
 
 
}
