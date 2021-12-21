# Rabbit Air Protocol

* `OTA_RABBIT_AIR_ADDRESS` `https://ota.rabbitair.com` (AWS: 54.82.241.61)
* Setup UDP
	* `RABBITAIR_SETUP_LOCAL_IP_ADDRESS = "192.168.10.1"`
	* `RABBITAIR_SETUP_LOCAL_PORT = 9009`
* `API_KEY` `f3f9e6e0d90bfe15a5ddfc7bdb283ff8`
* `API_KEY_JAPAN` `863143afaab8f756d039f0a65c114f6d`
* AWS Client `au32ip2ri54us-ats.iot.us-east-1.amazonaws.com`
* MQTT Helper ENDPOINT `au32ip2ri54us-ats.iot.us-east-1.amazonaws.com`
* userKey `00112233445566778899AABBCCDDEEF2` + `random_char("0123456789ABCDEF")`
* BLE
	* `COMMAND_CHARACTERISTIC_UUID` `53ef7d7d-c244-42bd-9064-a1569a521ca9`
   * `COMMAND_SERVICE_UUID` `366048ae-9f36-43cf-8004-010c0c9fa52e`


State changes happen via firebase and protocol buffers


## Samples:

### Login

**Request**

```
curl -H 'Host: ota.rabbitair.com' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'User-Agent: rabbitair-ios-app/1.1.8 (com.rabbitair.ios; build:197; iOS 15.1.0) Alamofire/5.2.1' -H 'Accept-Language: en-US;q=1.0, pt-PT;q=0.9' --data-binary '{"email":"YOUR_USERNAME","password":"YOUR_PASSWORD"}' --compressed 'https://ota.rabbitair.com/restapi/null/users/login_by_pass'
```

**Response**

``` {
	"token": "some_token", // Used in url from here on
	"userName": "Sometime",
	"tpCst": "shopify",
	"shopifyToken": "shopify_token"
} ```


### Location List

**Request**

```
curl -H 'Host: ota.rabbitair.com' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'User-Agent: rabbitair-ios-app/1.1.8 (com.rabbitair.ios; build:197; iOS 15.1.0) Alamofire/5.2.1' -H 'Accept-Language: en-US;q=1.0, pt-PT;q=0.9' --data-binary '{"options":""}' --compressed 'https://ota.rabbitair.com/restapi/some_token/users/location_list'
```

**Response**

```
{
	"locations": [{
		"_id": "34534",
		"name": "Blah2",
		"user_id": "23623425",
		"units": [{
			"_id": "23452345232",
			"serial": "547645754675",
			"user_key": "234523452435",
			"location_name": "Island living room",
			"thing_name": "234532542345",
			"name": "Blah2",
			"type": "MinusA2",
			"user_id": "43563456",
			"token_name": "arn:aws:iot:us-east-1:3456:thing/3456",
			"location_id": "3456",
			"control_type": "cloud",
			"filter_expired": false,
			"mcu": "2.3.15",
			"firmware": [3]
		}]
	}, {
		"_id": "12345",
		"name": "Blah1",
		"user_id": "1234",
		"units": [{
			"_id": "2345",
			"control_type": "cloud",
			"bt_mac_address": "",
			"user_key": "456745674576",
			"name": "York Living Room",
			"model": "1",
			"location_name": "York",
			"thing_name": "345643563456",
			"serial": "23452346",
			"type": "MinusA2",
			"user_id": "234523452345",
			"token_name": "arn:aws:iot:us-east-1:2345:thing/2345",
			"location_id": "754765467",
			"filter_expired": false,
			"mcu": "2.3.15",
			"firmware": [3]
		}]
	}]
}
```
### Update AWS Token

**Request**

```
curl -H 'Host: ota.rabbitair.com' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'User-Agent: rabbitair-ios-app/1.1.8 (com.rabbitair.ios; build:197; iOS 15.1.0) Alamofire/5.2.1' -H 'Accept-Language: en-US;q=1.0, pt-PT;q=0.9' --data-binary '{"options":""}' --compressed 'https://ota.rabbitair.com/restapi/some_token/users/update_aws_token'
```

**Response**

```
{
	"AccessKeyId": "AKJDLJFLD",
	"SecretAccessKey": "qwkjerlk",
	"SessionToken": "klwkqr;kqwerk;",
	"Expiration": "2021-12-07T23:22:50.000Z"
}
```

### Set User Firebase Token

**Requets**

```
curl -H 'Host: ota.rabbitair.com' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'User-Agent: rabbitair-ios-app/1.1.8 (com.rabbitair.ios; build:197; iOS 15.1.0) Alamofire/5.2.1' -H 'Accept-Language: en-US;q=1.0, pt-PT;q=0.9' --data-binary '{"firebase_token":"asdfsadf","email":"blah@example.com"}' --compressed 'https://ota.rabbitair.com/restapi/some_token/users/setUserFirebaseToken'
```

**Response**

```
{
	"lastErrorObject": {
		"n": 1,
		"updatedExisting": true
	},
	"value": {
		"_id": "ff789a9080b",
		"email": "blah@example.com",
		"first_name": "Somefirstname",
		"geo": "US",
		"last_name": "Somelastname",
		"verified_email": true,
		"_s_customer": "shopify",
		"tokens": [{
			"token": "some_token2",
			"_dt": "2020-09-18T20:01:02.520Z",
			"_dtexp": "2021-09-18T20:01:02.000Z",
			"tz": null,
			"_dtlast": "2021-12-07T22:14:06.480Z"
		}, {
			"token": "some_token",
			"_dt": "2021-12-07T22:22:49.884Z",
			"_dtexp": "2022-12-07T22:22:49.000Z",
			"tz": null,
			"_dtlast": "2021-12-07T22:22:50.281Z"
		}],
		"firebase_token": []
	},
	"ok": 1
}
```


## Rabbit Air API

* POST `restapi/access_token/users/activate_account`
	* Fields
		* `password`
* POST `restapi/access_token/users/shopify_addresses_delete`
	* Fields
		* `customer_id`
		* `address_id`
* POST `restapi/access_token/users/check_pin_code`
	* Fields
		* `email`
		* `pin`
* POST `restapi/access_token/users/location_list`
* POST `restapi/access_token/users/serialByMac`
	* Fields
		* `mac`
* POST `restapi/access_token/users/getThingShadow`
	* Fields
		* `thingName`
		* `timestamp`
* POST `restapi/access_token/users/getUserEccube`
	* Fields
		* `email`
* POST `restapi/access_token/users/getUserFullInfo`
* POST `restapi/access_token/users/login_by_pass`
	* Fields
		* `email`
		* `password`
* POST `restapi/access_token/users/login_v2`
	* Fields
		* `email`
* POST `restapi/access_token/users/register_user`
	* Fields
		* `first_name`
		* `last_name`
		* `first_name_kurihana`
		* `last_name_kurihana`
		* `zip1`
		* `zip2`
		* `company_name`
		* `prefecture`
		* `address1`
		* `address2`
		* `phone1`
		* `phone2`
		* `phone3`
		* `email`
		* `email1`
		* `password`
		* `password1`
		* `secret_question`
		* `answer`
		* `geo`
* POST `restapi/access_token/users/removeUserFirebaseToken`
	* Fields
		* `email`
		* `firebase_token`
* POST `restapi/access_token/users/reserve_thing_name`
	* Fields
		* `serial`
* POST `restapi/access_token/users/reset_password_or_activate`
	* Fields
		* `password`
		* `pin`
* POST `restapi/access_token/users/send_email_pin`
* POST `restapi/access_token/users/setUserFirebaseToken`
	* Fields
		* `email`
		* `firebase_token`
* POST `restapi/access_token/users/test_shop`
	* Fields
		* `email`
* POST `restapi/access_token/users/unit_create`
	* Fields
		* `name`
		* `type`
		* `location_name`
		* `serial`
		* `thing_name`
		* `user_key`
		* `control_type`
		* `bt_mac_address`
		* `model`
* POST `restapi/access_token/users/unit_delete
	* Fields
		* `_id`
* POST `restapi/access_token/users/unit_exist`
	* Fields
		* `name`
		* `serial`
* POST `restapi/access_token/users/update_aws_token`
* POST `restapi/access_token/users/editUnitNameAndLocation`
	* Fields
		* `_id`
		* `name`
		* `lid`
		* `lname`
		* `user_key`
		* `control_type`
		* `thing_name`
* POST `restapi/access_token/users/updateUserEccube`
	* Fields
		* `firstName`
		* `lastName`
		* `firstNameKurihana`
		* `lastNameKurihana`
		* `zip1`
		* `zip2`
		* `prefecture`
		* `address1`
		* `address2`
		* `phone1`
		* `phone2`
		* `phone3`
		* `email`
* POST `restapi/access_token/users/updateUserShopifyInfo`




## Misc Setup Stuff


### Rabbit Air Wireless

```
data : "Rabbit Air Wireless Data"
id
```

### Rabbit Air Wireless Data

```
country
dhcp
dns1
dns2
gateway
ip
mask
networks [Array of RabbitairWirelessNetwork]
security
ssid
        
```

### Rabbit Air Wireless Network

```
security (int)
ssid
```

### Encryption Key

```
Encryption Key Spec: AES
```


### Encrypte Message

```
byte[] encryptMessage(byte[] data, Key key) {
    Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
    instance.init(1, key);
    byte[] doFinal = instance.doFinal(data);
    byte[] iv = instance.getIV();
    byte[] result = new byte[(doFinal.length + iv.length)];
    System.arraycopy(doFinal, 0, result, 0, doFinal.length);
    System.arraycopy(iv, 0, result, doFinal.length, iv.length);
    return result;
}

```

### Decrypt Message


```
byte[] decryptMessage(byte[] data, java.security.Key key) throws Exception {
    if (data >= 32) {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Arrays.copyOfRange(data, data - 16, data));
        Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
        instance.init(2, key, ivParameterSpec);
        return instance.doFinal(data, 0, data - 16);
    }
    throw new Exception("Message too short");
}
``` 