package vendorpkg

func Vulnerable() string {
	return "vulnerable behavior executed"
}

func Wrapper() string {
	return Vulnerable()
}

func Safe() string {
	return "safe behavior"
}
