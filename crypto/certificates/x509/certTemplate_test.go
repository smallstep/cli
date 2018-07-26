package x509

import (
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	cmp "github.com/google/go-cmp/cmp"
	"github.com/smallstep/cli/pkg/x509"
)

func Test_NotBeforeAfter(t *testing.T) {
	var expected string
	var ctv *CertTemplate

	// NotBefore zero defaults to Now
	duration := time.Hour * 24 * 365 * 5
	ct, err := NewCertTemplate(NotBeforeAfter(time.Time{}, duration))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.NotBefore = time.Now().UTC()
			ctv.NotAfter = ctv.NotBefore.Add(duration)
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// Duration 0 uses default
	ct, err = NewCertTemplate(NotBeforeAfter(time.Time{}, 0))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.NotBefore = time.Now().UTC()
			ctv.NotAfter = ctv.NotBefore.Add(defaultDuration)
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// Duration < 0 returns error
	_, err = NewCertTemplate(NotBeforeAfter(time.Time{}, -1))
	if err == nil {
		t.Errorf("expected: <error>, but got `nil`")
	} else {
		expected = "Duration must be greater than 0"
		if strings.Compare(err.Error(), expected) != 0 {
			t.Errorf("error mismatch -- expected: `%s ...`, but got: `%s`",
				expected, err.Error())
		}
	}

	// Duration negative returns error
	_, err = NewCertTemplate(NotBeforeAfter(time.Time{}, -1))
	if err == nil {
		t.Errorf("expected: <error>, but got `nil`")
	} else {
		expected = "Duration must be greater than 0"
		if strings.Compare(err.Error(), expected) != 0 {
			t.Errorf("error mismatch -- expected: `%s ...`, but got: `%s`",
				expected, err.Error())
		}
	}

	// NotBefore and Duration set
	now := time.Now().UTC()
	duration = time.Hour * 24 * 365 * 5
	start := now.Add(time.Hour * 24 * 365 * 1)
	ct, err = NewCertTemplate(NotBeforeAfter(start, duration))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.NotBefore = start
			ctv.NotAfter = start.Add(duration)
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// Overwritten
	now = time.Now().UTC()
	duration = time.Hour * 24 * 365 * 5
	start = now.Add(time.Hour * 24 * 365 * 1)
	ct, err = NewCertTemplate(NotBeforeAfter(start, duration),
		NotBeforeAfter(time.Time{}, 0))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}
}

func Test_CRLSign(t *testing.T) {
	var ctv *CertTemplate

	// false
	ct, err := NewCertTemplate(CRLSign(false))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// true
	ct, err = NewCertTemplate(CRLSign(true))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.KeyUsage |= x509.KeyUsageCRLSign
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// true -> false
	ct, err = NewCertTemplate(CRLSign(true), CRLSign(false))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// true -> false -> true
	ct, err = NewCertTemplate(CRLSign(true), CRLSign(false), CRLSign(true))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.KeyUsage |= x509.KeyUsageCRLSign
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}
}

func Test_Hosts(t *testing.T) {
	var ctv *CertTemplate
	var ct *CertTemplate

	// empty throws error
	hosts := ""
	_, err := NewCertTemplate(Hosts(hosts))
	if err != nil {
		expected := "hosts cannot be empty"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	} else {
		t.Errorf("expected <error> but not <nil>")
	}

	hosts = "127.0.0.1"
	ct, err = NewCertTemplate(Hosts(hosts))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	hosts = "127.0.0.1,smallstep.com,8.8.8.8,google.com"
	ct, err = NewCertTemplate(Hosts(hosts))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.DNSNames = []string{"smallstep.com", "google.com"}
			ctv.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("8.8.8.8")}
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	h1 := "127.0.0.1,smallstep.com,8.8.8.8,google.com"
	h2 := "1.1.1.1,facebook.com"
	ct, err = NewCertTemplate(Hosts(h1), Hosts(h2))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.DNSNames = []string{"smallstep.com", "google.com", "facebook.com"}
			ctv.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("8.8.8.8"),
				net.ParseIP("1.1.1.1")}
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}
}
func Test_SerialNumber(t *testing.T) {
	var ctv *CertTemplate
	var err error
	var expected string

	// nil pointer returns error
	_, err = NewCertTemplate(SerialNumber(nil))
	if err == nil {
		t.Error("expected: <error>, but got: nil")
	} else {
		expected = "SerialNumber cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s ...`, but got: `%s`",
				expected, err.Error())
		}
	}

	// empty string returns errordefaults to random
	sn := ""
	_, err = NewCertTemplate(SerialNumber(&sn))
	if err == nil {
		t.Error("expected: <error>, but got: nil")
	} else {
		expected = "SerialNumber cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s ...`, but got: `%s`",
				expected, err.Error())
		}
	}

	// NaN returns error
	sn = "shake and bake"
	_, err = NewCertTemplate(SerialNumber(&sn))
	if err == nil {
		t.Error("expected: <error>, but got: nil")
	} else {
		expected = "Failed to parse serial number: "
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s ...`, but got: `%s`",
				expected, err.Error())
		}
	}

	// valid value modifies SerialNumber
	var success bool
	sn = "51"
	ct, err := NewCertTemplate(SerialNumber(&sn))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.SerialNumber, success = new(big.Int).SetString(sn, 10)
			if !success {
				t.Errorf("New big.Int failure")
			} else {
				if !reflect.DeepEqual(ctv.SerialNumber, ct.SerialNumber) {
					t.Errorf("SerialNumber mismatch -- expected: `%s`, but got: `%s`",
						ctv.SerialNumber.String(), ct.SerialNumber.String())
				}
			}
		}
	}
}

func Test_Subject(t *testing.T) {
	var ctv *CertTemplate
	var pn PkixName

	// Empty
	ct, err := NewCertTemplate(Subject(PkixName{}))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// with values
	pn = PkixName{
		Country:      []string{"usa"},
		Organization: []string{"smallstep"},
		Locality:     []string{"san francisco"},
		CommonName:   "internal.smallstep.com",
	}
	ct, err = NewCertTemplate(Subject(pn))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.Subject.Country = []string{"usa"}
			ctv.Subject.Organization = []string{"smallstep"}
			ctv.Subject.Locality = []string{"san francisco"}
			ctv.Subject.CommonName = "internal.smallstep.com"
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}
}

func Test_Issuer(t *testing.T) {
	var ctv *CertTemplate
	var pn PkixName

	// Empty
	ct, err := NewCertTemplate(Issuer(PkixName{}))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// with values
	pn = PkixName{
		Country:      []string{"usa"},
		Organization: []string{"smallstep"},
		Locality:     []string{"san francisco"},
		CommonName:   "internal.smallstep.com",
	}
	ct, err = NewCertTemplate(Issuer(pn))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.Issuer.Country = []string{"usa"}
			ctv.Issuer.Organization = []string{"smallstep"}
			ctv.Issuer.Locality = []string{"san francisco"}
			ctv.Issuer.CommonName = "internal.smallstep.com"
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}
}

func Test_BasicConstraints(t *testing.T) {
	var ctv *CertTemplate
	var ct *CertTemplate
	var err error
	var expected string

	// unset
	ct, err = NewCertTemplate()
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// if BasicConstraintsValid==false and IsCA=true then error
	ct, err = NewCertTemplate(BasicConstraints(false, true, 0))
	if err != nil {
		expected = "isCA must be `false` if `BasicConstraintsValid==false`"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s`, but got: `%s`",
				expected, err)
		}
	} else {
		t.Errorf("expected: `error`, but got: `nil`")
	}

	// BCV==false and IsCA false
	ct, err = NewCertTemplate(BasicConstraints(false, false, 0))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// BCV==false and IsCA false
	ct, err = NewCertTemplate(BasicConstraints(true, true, 0))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.IsCA = true
			ctv.KeyUsage |= x509.KeyUsageCertSign
			ctv.BasicConstraintsValid = true
			ctv.MaxPathLen = 0
			ctv.MaxPathLenZero = true
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// overwrite
	ct, err = NewCertTemplate(BasicConstraints(true, true, 0), BasicConstraints(true, false, 0))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.IsCA = false
			ctv.BasicConstraintsValid = true
			ctv.MaxPathLen = 0
			ctv.MaxPathLenZero = true
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// BCV==true and maxPathLen < 0 returns error
	ct, err = NewCertTemplate(BasicConstraints(true, false, -4))
	if err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected = "MaxPathLen must be >= 0"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s`, but got: `%s`",
				expected, err)
		}
	}

	// explicitly set MaxPathlen to 0
	mpl := 0
	ct, err = NewCertTemplate(BasicConstraints(true, false, mpl))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ct.MaxPathLen != mpl {
			t.Errorf("MaxPathLen -- expected: `%d`, but got: `%d`",
				mpl, ct.MaxPathLen)
		}
		if ct.MaxPathLenZero != true {
			t.Errorf("MaxPathLenZero mismatch -- expected: `%t`, but got: `%t`",
				true, ct.MaxPathLenZero)
		}
	}

	// MaxPathLen non-zero
	mpl = 3
	ct, err = NewCertTemplate(BasicConstraints(true, false, mpl))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.BasicConstraintsValid = true
			ctv.MaxPathLen = mpl
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// overwrite MaxPathLen
	ct, err = NewCertTemplate(BasicConstraints(true, false, 3), BasicConstraints(true, false, 0))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.BasicConstraintsValid = true
			ctv.MaxPathLen = 0
			ctv.MaxPathLenZero = true
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// BCV==false and maxPathLen != 0 returns error
	ct, err = NewCertTemplate(BasicConstraints(false, false, 5))
	if err != nil {
		expected = "maxPathLen should be set to 0 if `BasicConstraintsValid==false`"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s`, but got: `%s`",
				expected, err)
		}
	} else {
		t.Errorf("expected: `error`, but got: `nil`")
	}

	// overwrite MaxPathLen
	ct, err = NewCertTemplate(BasicConstraints(false, false, 0),
		BasicConstraints(true, true, 3), BasicConstraints(false, false, 0))
	if err != nil {
		t.Errorf("NewCertTemplate: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}
}

func Test_NewCertTemplate(t *testing.T) {
	var ctv *CertTemplate

	// empty
	ct, err := NewCertTemplate()
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ct.SerialNumber == nil {
			t.Errorf("SerialNumber cannot be nil. A random one should have been created")
		}
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}

	// error
	sn := "shake and bake"
	hosts := "google.com,127.0.0.1"
	ct, err = NewCertTemplate(Hosts(hosts), SerialNumber(&sn), BasicConstraints(true, true, 0))
	if err == nil {
		t.Error("expected: <error>, but got: nil")
	} else {
		expected := "Failed to parse serial number: "
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("bad error message -- expected: `%s ...`, but got: `%s`",
				expected, err.Error())
		}
	}

	// with values
	sn = "51"
	hosts = "google.com,127.0.0.1,facebook.com,1.1.1.1"
	now := time.Now().UTC()
	duration := time.Hour * 24 * 365 * 5
	start := now.Add(time.Hour * 24 * 365 * 1)
	pn := PkixName{
		Country:      []string{"usa"},
		Organization: []string{"smallstep"},
		Locality:     []string{"san francisco"},
		CommonName:   "internal.smallstep.com",
	}
	ct, err = NewCertTemplate(Hosts(hosts), BasicConstraints(true, true, 0),
		Subject(pn), Issuer(pn), NotBeforeAfter(start, duration))
	if err != nil {
		t.Errorf("NewCertTemplate error: %s", err)
	} else {
		if ctv, err = NewCertTemplate(); err != nil {
			t.Errorf("NewCertTemplate error: %s", err)
		} else {
			ctv.NotBefore = start
			ctv.NotAfter = start.Add(duration)
			ctv.Subject.Country = []string{"usa"}
			ctv.Subject.Organization = []string{"smallstep"}
			ctv.Subject.Locality = []string{"san francisco"}
			ctv.Subject.CommonName = "internal.smallstep.com"
			ctv.Issuer.Country = []string{"usa"}
			ctv.Issuer.Organization = []string{"smallstep"}
			ctv.Issuer.Locality = []string{"san francisco"}
			ctv.Issuer.CommonName = "internal.smallstep.com"
			ctv.DNSNames = []string{"google.com", "facebook.com"}
			ctv.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("1.1.1.1")}
			ctv.IsCA = true
			ctv.KeyUsage |= x509.KeyUsageCertSign
			ctv.BasicConstraintsValid = true
			ctv.MaxPathLen = 0
			ctv.MaxPathLenZero = true
			if err = ctv.Compare(*ct); err != nil {
				t.Errorf("%s", err)
			}
		}
	}
}

func Test_Locality(t *testing.T) {
	var err error
	var expected string
	var pn, pnv *PkixName

	// empty throws error
	locality := ""
	_, err = NewPkixName(Locality(locality))
	if err != nil {
		expected = "localities cannot be empty"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	} else {
		t.Errorf("expected: `error`, but got: `nil`")
	}

	// normal single
	locality = "boston"
	pn, err = NewPkixName(Locality(locality))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Locality: strings.Split(locality, ",")}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// normal list
	locality = "boston,philadelphia,manhattan"
	pn, err = NewPkixName(Locality(locality))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Locality: strings.Split(locality, ",")}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// overwrite
	l1 := "brazil,italy,sudan"
	l2 := "ukraine,russia,china"
	pn, err = NewPkixName(Locality(l1), Locality(l2))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Locality: append(strings.Split(l1, ","), strings.Split(l2, ",")...)}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}
}

func Test_Country(t *testing.T) {
	var err error
	var expected string
	var pn, pnv *PkixName

	// empty throws error
	pn, err = NewPkixName(Country(""))
	if err != nil {
		expected = "countries cannot be empty"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	} else {
		pnv = &PkixName{}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// normal single
	country := "brazil"
	pn, err = NewPkixName(Country(country))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Country: strings.Split(country, ",")}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// normal list
	country = "brazil,italy,sudan"
	pn, err = NewPkixName(Country(country))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Country: strings.Split(country, ",")}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// overwrite
	c1 := "brazil,italy,sudan"
	c2 := "ukraine,russia,china"
	pn, err = NewPkixName(Country(c1), Country(c2))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Country: append(strings.Split(c1, ","), strings.Split(c2, ",")...)}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}
}

func Test_Organization(t *testing.T) {
	var err error
	var expected string
	var orgs string
	var pn, pnv *PkixName

	// empty throws error
	orgs = ""
	pn, err = NewPkixName(Organization(orgs))
	if err != nil {
		expected = "orgs cannot be empty"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	} else {
		pnv = &PkixName{}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// normal single
	orgs = "smallstep"
	pn, err = NewPkixName(Organization(orgs))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Organization: strings.Split(orgs, ",")}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// normal list
	orgs = "smallstep,betable,oracle"
	pn, err = NewPkixName(Organization(orgs))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Organization: strings.Split(orgs, ",")}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// overwrite
	org1 := "smallstep,betable,oracle"
	org2 := "google,facebook,apple"
	pn, err = NewPkixName(Organization(org1), Organization(org2))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{Organization: append(strings.Split(org1, ","), strings.Split(org2, ",")...)}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}
}

func Test_CommonName(t *testing.T) {
	var err error
	var expected string
	var pn, pnv *PkixName

	// empty throws error
	cn := ""
	pn, err = NewPkixName(CommonName(cn))
	if err != nil {
		expected = "common cannot be empty"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch -- expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	} else {
		pnv = &PkixName{}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// normal
	cn = "internal.smallstep.com"
	pn, err = NewPkixName(CommonName(cn))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{CommonName: cn}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}

	// overwrite
	cn = "internal.smallstep.com"
	cn2 := "smallstep.com"
	pn, err = NewPkixName(CommonName(cn), CommonName(cn2))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv = &PkixName{CommonName: cn2}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}
}

func Test_NewPkixName(t *testing.T) {
	cn := "internal.smallstep.com"
	country := "brazil,italy,sudan"
	org := "smallstep,betable,oracle"
	locality := "boston,philadelphia,manhattan"
	pn, err := NewPkixName(CommonName(cn), Organization(org), Country(country),
		Locality(locality))
	if err != nil {
		t.Errorf("NewPkixName: %s", err)
	} else {
		pnv := &PkixName{
			Organization: strings.Split(org, ","),
			Locality:     strings.Split(locality, ","),
			Country:      strings.Split(country, ","),
			CommonName:   cn,
		}
		if !cmp.Equal(pnv, pn) {
			t.Errorf("data mismatch")
		}
	}
}
