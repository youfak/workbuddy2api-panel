package apikey

import "testing"

func TestCreateReturnsVerifiableKeyAndMaskedRecord(t *testing.T) {
	record, plain, err := Create("cli")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(plain, []Record{record}) {
		t.Fatal("created key did not verify")
	}
	if record.Name != "cli" || record.ID == "" || record.Hash == "" || record.Masked == plain || record.Masked[:3] != "sk-" {
		t.Fatalf("unsafe record: %+v", record)
	}
	if Verify("sk-not-the-created-key", []Record{record}) {
		t.Fatal("wrong key verified")
	}
}
