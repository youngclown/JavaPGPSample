import org.bouncycastle.openpgp.PGPException;

import java.io.*;
import java.security.NoSuchProviderException;

public class TestPGP {

    private boolean isArmored = false;
//    	private String id = "ymkim";
	private String passwd = "test";
    private boolean integrityCheck = true;


    private String pubKeyString = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: BCPG C# v1.6.1.0\n" +
            "\n" +
            "mQENBFy6xh4BCAC+2n+lwq1f7JJj8bMJoK3w8WlMx3DsLxi4y+a5Xq1/GKz99Wuv\n" +
            "pqFICr7Fk5UIQLf9XkIKMVHvOanfPRUuOUezyygtM4K9zmuXmW6LGJfTssg71YuF\n" +
            "3lqSKghXe1vfnFYG2OSeceU/UdzWo3sBRumL2G/yv0QHVkPTzxVKu+vDUpHamvBr\n" +
            "5P9BgvjbWi2Da5q/HXMYCq1TuLhpQRyA8393GDDBhySlJrALlBXPdxJaLJgmAeF5\n" +
            "y/FywMaXk0qUz/GbqdYW7uvQRM6e+r7489teBe3D17TzxgP7oF88jfKwR/1f0V+e\n" +
            "l9EMFBPqeAwXy1JOG87Kdh9UYmGm9ZZubD8fABEBAAG0B2VubGlwbGWJARwEEAEC\n" +
            "AAYFAly6xh4ACgkQHf/KWqpHOl7EbggAjvrylSgXKq2RMGoXuoHY/Uyjw5+zqOyp\n" +
            "a6qiXs8oNrPUSeZVA61Eho/YE0OkThRWhK1PPYPIzbF9BVoiCv5htVWR5/lY4YNC\n" +
            "8KWZB2F8UPTEukJdp6hQXb5iBOvg7sBH5yAsAVZ32bHSEjUjMmoEVrF7g862EK9I\n" +
            "S+IxmgjIRyenRqjh6WLiprv3y1k7ricLtD5GjZBlgu/UaVtZttm2/Pti3LF8oGQF\n" +
            "FSbzm34Yb3eodIBu0fxbWPNTDKiCWLRdKTTNzHXY6S0ZlJaFXIpu4AYT3Dz++tRF\n" +
            "7w4ENl64DxuNjJNMxw7HdKOL0E/zQ67nJCB+ZFUuFULG+bJWzsXLdQ==\n" +
            "=Vh4J\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private String privKeyString = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG C# v1.6.1.0\n" +
            "\n" +
            "lQOsBFy6xh4BCAC+2n+lwq1f7JJj8bMJoK3w8WlMx3DsLxi4y+a5Xq1/GKz99Wuv\n" +
            "pqFICr7Fk5UIQLf9XkIKMVHvOanfPRUuOUezyygtM4K9zmuXmW6LGJfTssg71YuF\n" +
            "3lqSKghXe1vfnFYG2OSeceU/UdzWo3sBRumL2G/yv0QHVkPTzxVKu+vDUpHamvBr\n" +
            "5P9BgvjbWi2Da5q/HXMYCq1TuLhpQRyA8393GDDBhySlJrALlBXPdxJaLJgmAeF5\n" +
            "y/FywMaXk0qUz/GbqdYW7uvQRM6e+r7489teBe3D17TzxgP7oF88jfKwR/1f0V+e\n" +
            "l9EMFBPqeAwXy1JOG87Kdh9UYmGm9ZZubD8fABEBAAH/AwMCH9nOCpOWxHdgdV3s\n" +
            "2p2O7g2cRV+jFWc5GcRpwPmfLTjSzOh0OJ082O6zNGx9bc/5VfECNwhoqMfqaAlm\n" +
            "Bf859eunFNTSyRaw/GVfhXE7LeDzO2OQSzWk+oiuwex4ACkLPS9XhP1RWbx7orAF\n" +
            "MsdoHtfME58XO8zxgIkg3MNNY99bAd2bUHPAEhPJhhORXe0aK/AHXAdx+nOCP+WK\n" +
            "W7WuATVyzXPnjIpyUxs2tpZX0A/eVVSulZT1RW7jXzXLk9ealbnErPWHdy7qzA3x\n" +
            "VRhUD45dsN6uTsfJWK+QKh1Ap/uSh1AQGD1iqrUP8nYbEdSQPFFanSDw/KBhO3fS\n" +
            "s5mYft1+cqkm6sxIJ/NtyLyarhBbBMgK1bxWjMyn9YUjOlXSfg2oLSXbni2eQo+p\n" +
            "GJqUF9WA/idPGu4mJu9fndopCK0D/P5GSoSUT1T0quNFlhbhRx8/f0xMEVSUG8OF\n" +
            "7fJYCkTiQbAmBZTA7ujDDUj6MyaN+dvQgKDb5Fj8CYQBCnEhCmN5D/SDlW2FEIUh\n" +
            "7Yh8j5eXN0XLxoCTZWhRgSFdwhsYeB4SSljDn3eKVbXTi7JtKtfzKAvMq008FJBa\n" +
            "ES5cZezUmw2mPmxvKt+uSHH18mYp7DlczRzUijj1YY5sYDgMaqdwGBx8L1aWKUw9\n" +
            "1gnatwbCAxmxR0PH2a5sXeJY0Lqz61LMlWZy9ckMirYcciJss+jFnyh/yGCGOK7x\n" +
            "7EWXAwU6PYZy6EHVfQX8BXpeIcxvdK0m3/dUf0t+SmIJ+n7BsKt4Tc8blRBakVMU\n" +
            "3faVNGjFzO7LLzr4FRIAFkCjQEu9HZ2rbX+5WJdxpGUhniFfPjbswfLdfTL9Mmlq\n" +
            "QGSilXzGbnyyTGK1vXR9ECOevahthKC/MPKj7LM5AbQHZW5saXBsZYkBHAQQAQIA\n" +
            "BgUCXLrGHgAKCRAd/8paqkc6XsRuCACO+vKVKBcqrZEwahe6gdj9TKPDn7Oo7Klr\n" +
            "qqJezyg2s9RJ5lUDrUSGj9gTQ6ROFFaErU89g8jNsX0FWiIK/mG1VZHn+Vjhg0Lw\n" +
            "pZkHYXxQ9MS6Ql2nqFBdvmIE6+DuwEfnICwBVnfZsdISNSMyagRWsXuDzrYQr0hL\n" +
            "4jGaCMhHJ6dGqOHpYuKmu/fLWTuuJwu0PkaNkGWC79RpW1m22bb8+2LcsXygZAUV\n" +
            "JvObfhhvd6h0gG7R/FtY81MMqIJYtF0pNM3MddjpLRmUloVcim7gBhPcPP761EXv\n" +
            "DgQ2XrgPG42Mk0zHDsd0o4vQT/NDruckIH5kVS4VQsb5slbOxct1\n" +
            "=vG5x\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private String plainTextFile = "C:\\sample\\plain-text.txt"; //create a text file to be encripted, before run the tests
    private String cipherTextFile = "C:\\sample\\cypher-text.txt";
    private String decPlainTextFile = "C:\\sample\\dec-plain-text.txt";


    public void encrypt() throws NoSuchProviderException, IOException, PGPException{
        InputStream pubKeyIs = new ByteArrayInputStream(pubKeyString.getBytes());
        FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
        PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
        cipheredFileIs.close();
        pubKeyIs.close();
    }

    public void decrypt() throws Exception{
        FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
        InputStream privKeyIn = new ByteArrayInputStream(privKeyString.getBytes());
        FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
        PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
        cipheredFileIs.close();
        plainTextFileIs.close();
        privKeyIn.close();
    }

    public static void main(String[] args) {
        TestPGP testPGP = new TestPGP();
        try {
            testPGP.encrypt();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }


        try {
            testPGP.decrypt();
        } catch (Exception e) {
            e.printStackTrace();
        }



    }

}
