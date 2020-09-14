public class LicenseUtils {
 
    /**
     * DES������Կ��DES��Ҫ16λ���ַ����ܣ�������Կ��8λ��Ҳ�����Զ���λ
     */
    private static final String password = "aaaaaaaa";
 
    /**
     * ��ȡ�豸�����룺��Ҫ�ǽ���ȡ��Ӳ����Ϣͨ��ɢ�м�������Ψһ�Ļ�����
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
     * ��ȡ��Կ,��Կ����Ĭ�Ϸ���resource����
     *
     * @return
     */
    public static String getPublicKey() throws IOException {
        ClassPathResource pathResource = new ClassPathResource("publicKey.txt");
        InputStream inputStream = pathResource.getInputStream();
        return new String(ByteStreams.toByteArray(inputStream));
    }
 
 
    /**
     * ���ܣ���ʹ��DES��HEX�����Ժ���ʹ�ù�Կ���ǶԳƽ���
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
