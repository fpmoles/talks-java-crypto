package com.frankmoley.utilities.crypto.signature;

import org.junit.jupiter.api.Test;
import org.relaxng.datatype.Datatype;

import javax.xml.bind.DatatypeConverter;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Frank P. Moley III.
 */
class SignatureUtilitiesTest {

    private static final String RSA = "RSA";
    private static final byte[] PUBLIC_KEY = DatatypeConverter.parseHexBinary("30820222300D06092A864886F70D01010105000382020F003082020A02820201009A7BAFAEC7E09E4D77F18EEDC8F4D8B37D9E84271554F44984293A9C96FB55BD973669C2649AC3A10E54385A8CE1C1E59F6943DFB97FA84B66E17F93057AF2F481EAF5FB6DA3AD307876F07D4C07551E1F945D9CD4A0C415C557487391237115E00C289B8FEB9734439AD911E0C2FF069D6BE37007E954325389A4FF6FEAC07EE371E35F99956A784F40E4571A8BCD6346B4129EEBFF329D9AEF33238729D000EA7ED2CD4701439E98C11DC744FE2913A7EF382B7491C2F244A74EEC65ACD43303017FADD6D3889762B986BE95A9D2F65B34CDC6B817ADE7011C4EAC9F335B086F383B4A56E03DF6E297D1EDFCC30F48F01961C90FFB7AA67A2467E0C6CADD4F267E9020422BE5F5C21950905F8C4FDE61AE69C0BE50FBC1B8BD25BDAF84967C083CA05D4DF6F0F98B3EBB3C2F362C239A33814B5B055036310A9ACDC87D90ECE7F802EAA58850F1374CAF0B464286BBA5F57B742553FC8BF06983E02FCC39FCED547A38936581B405AE97F0B28F76F659FD5D7554C86D194AB12B654E7D6F4148045F160F12D99F0BC431825547F54CAA389DB2480A00B615F33F93648E635AC832A67060FD8DFCE628D8E63CE262D88A2420EF27CA3DD493E2B63E73C676F60B26A64075136A2E825532C35BE1D6F69F75DF748A5F6C8EB7EFE5C3BAF6AA7D21342A304FFE6410B2EF920822E2359CBCF069F20BCD6F81FDB7CFF9383073A90203010001");
    private static final byte[] PRIVATE_KEY = DatatypeConverter.parseHexBinary("30820943020100300D06092A864886F70D01010105000482092D3082092902010002820201009A7BAFAEC7E09E4D77F18EEDC8F4D8B37D9E84271554F44984293A9C96FB55BD973669C2649AC3A10E54385A8CE1C1E59F6943DFB97FA84B66E17F93057AF2F481EAF5FB6DA3AD307876F07D4C07551E1F945D9CD4A0C415C557487391237115E00C289B8FEB9734439AD911E0C2FF069D6BE37007E954325389A4FF6FEAC07EE371E35F99956A784F40E4571A8BCD6346B4129EEBFF329D9AEF33238729D000EA7ED2CD4701439E98C11DC744FE2913A7EF382B7491C2F244A74EEC65ACD43303017FADD6D3889762B986BE95A9D2F65B34CDC6B817ADE7011C4EAC9F335B086F383B4A56E03DF6E297D1EDFCC30F48F01961C90FFB7AA67A2467E0C6CADD4F267E9020422BE5F5C21950905F8C4FDE61AE69C0BE50FBC1B8BD25BDAF84967C083CA05D4DF6F0F98B3EBB3C2F362C239A33814B5B055036310A9ACDC87D90ECE7F802EAA58850F1374CAF0B464286BBA5F57B742553FC8BF06983E02FCC39FCED547A38936581B405AE97F0B28F76F659FD5D7554C86D194AB12B654E7D6F4148045F160F12D99F0BC431825547F54CAA389DB2480A00B615F33F93648E635AC832A67060FD8DFCE628D8E63CE262D88A2420EF27CA3DD493E2B63E73C676F60B26A64075136A2E825532C35BE1D6F69F75DF748A5F6C8EB7EFE5C3BAF6AA7D21342A304FFE6410B2EF920822E2359CBCF069F20BCD6F81FDB7CFF9383073A902030100010282020051F167C81337DF60824DFC9DBEE9B984C40E7054F6E8C047BAB5CFE43DE6059DF276A774B8BEAB24642062600DB8B68C2199C9AA03906669D0A1AE7503042B996CCC803C24F51C29C8CC7656501CD79689F3BE10316D3175C6DEBC8CA8A11F1C1662FCAB3F951CF8591FEB22A3916B8B4BB76DC6003C512FFCC5D762B32FD779B715B32103AB90F54E3CC2A23D6F88BBAF4657563B227BEBC3C23BE30D902D483F1A94A0D49824111D3FDA96D7CEE5650AC046902E5E1F05394B71FECD13F6DF3429F85AF2C7F3FD311DEE0E6BFECFEB6387C7DB2FCD47AE70155EDA0BFC46BE5B987D42BA8069FDEA45D3D22430278C6DE758CA39131104FB67123ED5D3C7BD9FA1330B8EDC0FC88ED046E6BF09AB3334271BB22EE53F45FC52561FE0CDB97C2362E2F037ADA1F4041A2F39785B4D05F1EE30A31238D7E7C7F46CD1C46BE2B6C0C8DEA7453D6179D7A1175B93A9C62728554536C74834F7D39ECBF5D9A25279DB0235F74E833B1E32C859D5114F46EDC0BD31E3475E88FDCB1D4333625CE742D0A17178E5E80496B390262B548D7EB40F56E8F1D15DFC455432D3ADACBE6C859C05C90D8121E7A98F89A64EF340A34961158471F9CE4062628CEAF1A2135E3AB9CC82AE5C256ED7B8806ADCF61215138577CC53C3608A093CF2A7437055EFA8E59DDEC41791DA5BA93E963A72D22E1CB3E3996CF7013989052BF11B8867192D0282010100D7FBF4F5E65C229D964C3654C091F86C28F8BD7547F36CF2A3AB7C3120F3AD012969440D542A79F84D19E8E55F7E0978CCB30FE1C4B815C0102A55F4BD5BF76A4FE007FBE5BADDE274FBF66CD49AFA93A3A7CB88C8BBCBF5F4CF91AFD5DEAD0FD2B263734F5D9A4608AC27A91CDAA2643447884F490411A7063AB9E357F95F92E20E49E68BF304E9BAEA9B3665CAF78493ED9CBF34CBDB83BCF10DD4764F6BB5B4CA48C8B18D43E66AD87C6FEB50F21FADD6AC28E03E4BA12F0E756236E60AA602F2A383073488DE3ACB3E3A92F55BB73E4AB3CFD6BB5A9618F3190C4A394485F3B291B6C28D12B2D281CEEE77D3851182F04BFBF6818813A59C162E29EE3EFB0282010100B71AC25DDB5AA751BAFDAF95C7E0162DBB78FC7572CA69DA986F8B69D21B0A0F5AD0CF69CFE20F2C4382C5653DA90EE666B27A6E7E2033F811E5564E8B4AC94E5F09FC2EF9082C5C331EB07096552E4933F8B54D5E16EAE9D3A38D4F599864009604DF3266215B74BFD4DB79FBE74D7040A7F617A3C95CB7CAA6DE238CE5A75CDCFA9117A0A213B5ED098F247AFD18A272D6A7C76CF087A18737AC7739091A9FD237A11BC7A0797CC873AC6547FD8AC6BF224899C88EBC578F47FDF99B1BBB526913ABD2638A4D8CFE8D406D2D592EBE8C0E1B0E1F29A35CFE9ABCB10594D082E5513211B72B1804AD79702C1B8FF03715714D3E08FF397926486142032F86AB0282010100D4D63F30CACEE475B2946BBDDCFE7B75EA7224111CD42EFA747B1AA93735A9B8C95C286992154198843212256692C736B95183471219EDA514C9036767EAE6C766EAF8332CD196B2006203167FF43115A86243DA0925B6FA2B4318E7D3B3D98B0C302A7C892B4E49D16604B74BEDCFB53B277A95D6F821851C4866C238015043686C783AAE92CEB69D316FBE8D5513D11C0D3D37D70944CA6F38844E68401F7E32285CCD18DA829CDF91721EC01F465A1D6EBCBC932E104D4817D168F57C7FE5D465D2E7DE03D1145D8FC744E568CFF6A575EBF7D63D4E293770E7B00ABCA05FF824721F4D5CC39E607EF6B25C769E5D0151572F765D73011963D51FACC6505D0282010100910D2CBE877FA81ED1E017D1B2D62D1BAB70EBA5EAFAB8A287B18DA295E3FFB32C41509E452592D980DDBE9C361D90052B83E60353FD14CE46F703C913057AB5900A6BF1962C485FFDCB2900F7C6A0F532ABAA8C90A5DD10C12CC64BFEF0FEFF8BD86E2C11C6091A52C13FE0C19279C11C27328785A385C4BF503397BC0D4DE8FDD1AD51275A5DFCF7BB63DF05632CB9BBF99A4E1C59EB4825C30FE81E91BCBAB1208A8B64381725A7F222B6D531E05713A1081C7349C7A0218C6980EBC42B3FDCA7CDACCC580A995029FBC8C16CEDDFDB396D6B617A6DC4C499363391F552BCEF06C4804E37603E8C62305F70B2351C9DEAF4C2D903BEB6DF81E532132DFA230282010029103E7AE1FF9F6D1A25E08D0D72CB0B7A24219B2AE21E3120752D9CF15D143A538165F4AB2A5022F263E43657C8A4C267819F8BFDD85FFF9E9E6981AC2651F0D862C502BC2100BCA7440E058AA8D04DE9102B768AC3EC09E8DCDA08D838853279CE313685E6032743FD133D78C37114A836ED344E6F870D6898A55D7FAFCEAC2486DFF7EE982016D584FE7E07AA5BFBBEC517165E3ECC1C0CCAA10D61E3C5FD829F6D49003ADF11957F652218FF4B824E476172594B7050E4D1164844E5D92E642E0AD7DD18A0E31B63FFB1856EC7CD6E5D4F858EFFFE35220549EE176873DEDAF6AAAA0018F27DA1F526556523EF6D4517579572A5E65E4F88B889E943ED2D");
    private static final byte[] INPUT_BYTES = DatatypeConverter.parseHexBinary("E4197E3CC2AC5FB916CDD203750B565E5F71761DD34147F07CA7CC615985529D00931CC8F853C42FB8B82F049CA84C034427D57DA96C6815625DA47151AF6F8D");
    private static final byte[] SIGNATURE_BYTES = DatatypeConverter.parseHexBinary("5C7DFA2BCBF1A37F16EA40607911851C8D78387FEBDDA997BC80D19CA75F3C58D7714D1A90CFFFC4F5E6EB9D0E78CC3C1A6EDFF250F78860FF262EEBBDBF3AA4FF1E3157DDF02021AEFFEC5F4DE6D995081EC871A5601384EB918087F57E7069A2A1D59710ECFC723C8BA1767B89B9E41F3BB7B7AE948E54C91F46E0BB991371B6DBCB4A0241D5117A89779E2EF2E9225186DC20CCD93255E35187A801AC60D139CBF95945DDDEA3BF5AA6D14D9BEED0EC7FCEA770D2D4FD37BA394EEDD2136991B918D28BCBA9BA6459414981CA4B0DF892ED4802CA96B55257BB6DE2DA374FB36A9D74B4B4375574047CF3A2B0D216DF09585EB2E717C85D96534566443E44E000497E41FFB659DF8D154E1E64DDFE684D442BCAACF18574107FA67E80E422205FDA20B93BCD856F4A58895C842737B5C142B0C7107AFBB12673B2575212860F858F961C140F553D58AEF4D7C97D6A03AB25BFFBD942409AEFE5D192E9AD5D20E57E07D65D0A3712930B28E6996D640E916834697175156755D2DC5C10A68509DA4562432AEA95E79D1389E01BFACB96898E594D7510D70157F0977D5F81772F2C4199CDB4C9813AA934FF46CCEA9CB9466248C62C8CB6B044F9CA93887CD6363726FE9A00B57CB9721AA679991751DFAB1CDE85EB9A10C400E7E43A0728C88978E58E6A76ADF8FA66762D7EC3C4E7813E12EDB151550EDCFC1EC5FF9F02D4");

    @Test
    void getInstance() {
        SignatureUtilities utils = SignatureUtilities.getInstance();
        assertNotNull(utils);
        SignatureUtilities utils2 = SignatureUtilities.getInstance();
        assertSame(utils, utils2);
    }

    @Test
    void createDigitalSignature() throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(PRIVATE_KEY));
        byte[] signature = SignatureUtilities.getInstance().createDigitalSignature(INPUT_BYTES, privateKey);
        assertNotNull(signature);
    }

    @Test
    void verifyDigitalSignature() throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(PUBLIC_KEY));
        assertTrue(SignatureUtilities.getInstance().verifyDigitalSignature(INPUT_BYTES, SIGNATURE_BYTES, publicKey));
    }
}