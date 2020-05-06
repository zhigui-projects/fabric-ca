package gm

import "github.com/cloudflare/cfssl/log"
var(
	isGM = false
	isTLSGM = false
)
func IsGM() bool {
	return isGM
}
func SetGM(isgm bool){
	isGM = isgm
	log.IsGM = isgm
}
func IsTLSGM() bool{
	return isTLSGM
}
func SetTLSGM(istlsgm bool){
	isTLSGM = istlsgm
}