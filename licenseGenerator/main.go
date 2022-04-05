package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
)

type License struct {
	encKey1 string
	encKey2 string
	encKey3 string

	uuid string
}

const (
	defaultEncKey1 = "HKGWYF85JT3I0ANMP7SD2ZB9LOVXC64R"
	defaultEncKey2 = "CEHJG84QA1FK5TY62D0PNSW3ZBIOMRU7"
	defaultEncKey3 = "SAL39CLPIVKL275DQOXZT294L7ACYUI5"
)

func pkcs5Padding(text []byte) []byte {
	padding := aes.BlockSize - (len(text) % aes.BlockSize)
	return append(text, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func encryptASECBC(plainText []byte, key []byte, iv []byte) (cipherText []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf(fmt.Sprint(r))
		}
	}()

	var data = pkcs5Padding(plainText)

	cipherText = make([]byte, len(data))

	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText, data)

	return
}

// VALUE1, VALUE2 를 생성하는 함수
func (l *License) makeVals(payloads ...string) (string, string) {
	var v []string
	var h hash.Hash

	// VALUE1 생성 (SHA-256)
	// EncKey1+UUID
	v = []string{l.encKey1, l.uuid}

	h = sha256.New()
	h.Write([]byte(strings.Join(v, "")))

	val1 := hex.EncodeToString(h.Sum(nil))

	// VALUE2 생성 (SHA-256)
	// EncKey2+필드값들
	v = []string{l.encKey2}
	for _, p := range payloads {
		v = append(v, strings.Split(p, "=")...)
	}

	h = sha256.New()
	h.Write([]byte(strings.Join(v, "")))

	val2 := hex.EncodeToString(h.Sum(nil))

	return strings.ToUpper(val1), strings.ToUpper(val2)
}

// 라이선스 키를 생성하는 함수
func (l *License) genKey(payloads ...string) (string, error) {
	var err error
	var aes1, aes2 []byte

	// VALUE1, VALUE2 생성
	var val1, val2 = l.makeVals(payloads...)

	// AES1 생성 (ASE_256_CBC)
	// Key1: VALUE1(0~31 index, 32 bytes) / Data1: VALUE2(32~63 index, 32 bytes) / IV1: VALUE1(24~39 index, 16 bytes)
	if aes1, err = encryptASECBC([]byte(val2[32:]), []byte(val1[:32]), []byte(val1[24:40])); err != nil {
		return "", err
	}

	// AES2 생성 (ASE_256_CBC)
	// Key2: VALUE2(0~31 index, 32 bytes) / Data2: VALUE1(32~63 index, 32 bytes) / IV2: VALUE2(24~39 index, 16 bytes)
	if aes2, err = encryptASECBC([]byte(val1[32:]), []byte(val2[:32]), []byte(val2[24:40])); err != nil {
		return "", err
	}

	// 라이선스 키 생성 (MD5)
	// AES1+AES2
	h := md5.New()
	h.Write([]byte(strings.Join([]string{
		base64.StdEncoding.EncodeToString(aes1),
		base64.StdEncoding.EncodeToString(aes2),
	}, "")))

	key := hex.EncodeToString(h.Sum(nil))

	return strings.ToUpper(key), nil
}

// 라이선스 파일 내용 생성
func (l *License) genLic(payloads map[string]string) (string, error) {
	var props []string

	// payloads 를 property 리스트 형태로 변환
	for k, v := range payloads {
		props = append(props, fmt.Sprintf("%s=%s", k, v))
	}

	// 라이선스 키 생성
	key, err := l.genKey(props...)
	if err != nil {
		return "", err
	}

	// 라이선스 파일 내용 생성 (AES_256_CBC + Base64)
	// [LICENSE] key=LicenseKey 추가필드들(공백으로 연결)
	// Key: EncKey3(32 bytes), Data: 파일 내용, IV: EncKey3(8~23 index, 16 bytes)
	data := []string{"[LICENSE]", fmt.Sprintf("key=%s", key)}
	data = append(data, props...)

	lic, err := encryptASECBC(
		[]byte(strings.Join(data, " ")),
		[]byte(l.encKey3),
		[]byte(l.encKey3[8:24]),
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(lic), nil
}

// Generate 는 입력받은 payloads 로 라이선스 파일 내용을 생성해주는 함수이다.
func (l *License) Generate(payloads map[string]string) (string, error) {
	return l.genLic(payloads)
}

func newLicense(uuid string) *License {
	uuid = strings.ReplaceAll(uuid, "-", "")
	uuid = strings.ToUpper(uuid)

	return &License{
		encKey1: defaultEncKey1,
		encKey2: defaultEncKey2,
		encKey3: defaultEncKey3,
		uuid:    uuid,
	}
}
// ClusterTenant dd
type ClusterTenant struct {
	Name string `json:"name"`
}

// TenantCreateTaskInput 테넌트 생성 Task 의 Input
type TenantCreateTaskInput struct {
	Tenant ClusterTenant `json:"tenant"`
}

func getInput (in []byte) (interface{}, error) {
	var t TenantCreateTaskInput
	if err := json.Unmarshal(in, &t); err != nil {
		return nil, err
	}

	return &t, nil
}

func printInput(in interface{}) {
	if _, ok := in.(*TenantCreateTaskInput); ok {
		fmt.Printf("hello %v\n", in)
	} else {
		fmt.Println(in)
	}
}

func main() {
	/*data := `{ "tenant": {"name": "jcm"} }`
	r, err := getInput([]byte(data))
	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Printf("%T\n",r)

	printInput(r)*/
	payloads := map[string]string{
		"cdm_cloud_provider": "데이터커맨드",
		"cdm_cloud_customer": "현대자동차",
		"cdm_dr_issue_dt": "1629642231",
		"cdm_dr_expiry_dt": "1640960790",
		"cdm_dr_limits_platform": "unknown",
		"cdm_dr_limits_storage": "lvm,ceph",
		"cdm_dr_limits_cluster": "2",
		"cdm_dr_limits_tenant": "3",
		"cdm_dr_limits_instance": "100",
		"cdm_dr_limits_volume": "500",
		"cdm_r_issue_dt": "1629642231",
		"cdm_r_expiry_dt": "1640960790",
		"cdm_r_limits_agent": "500",
		"cdm_r_limits_group": "300",
	}

	l := newLicense("EBC64D56C-0A91-90DB-9AA2-297C9F24413")

	lic, err := l.Generate(payloads)
	if err != nil {
		fmt.Printf("%v\n", err)
	}

	fmt.Printf("nono : %s\n", lic)


}
