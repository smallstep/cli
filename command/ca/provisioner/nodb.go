package provisioner

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/linkedca"
)

type nodbCRUD struct {
	configFile string
	ctx        context.Context
	auth       *authority.Authority
}

func newAdminAPIDisabledClient(ctx context.Context, cfg *config.Config, cfgFile string) (*nodbCRUD, error) {
	a, err := authority.FromOptions(authority.WithConfig(cfg), authority.WithAdminDB(admin.NewNoDB()))
	if err != nil {
		return nil, fmt.Errorf("error loading authority: %w", err)
	}
	ndb := &nodbCRUD{
		configFile: cfgFile,
		ctx:        ctx,
		auth:       a,
	}
	if err := ndb.auth.ReloadAdminResources(ctx); err != nil {
		return nil, fmt.Errorf("error loading provisioners from config: %w", err)
	}
	return ndb, nil
}

func (ndb *nodbCRUD) CreateProvisioner(prov *linkedca.Provisioner) (*linkedca.Provisioner, error) {
	if err := ndb.auth.StoreProvisioner(ndb.ctx, prov); err != nil {
		return nil, fmt.Errorf("error storing provisioner: %w", err)
	}

	if err := ndb.write(); err != nil {
		return nil, err
	}

	return prov, nil
}

func (ndb *nodbCRUD) GetProvisioner(opts ...ca.ProvisionerOption) (*linkedca.Provisioner, error) {
	o := new(ca.ProvisionerOptions)
	if err := o.Apply(opts); err != nil {
		return nil, err
	}

	var (
		err  error
		prov provisioner.Interface
	)

	switch {
	case o.Name != "":
		prov, err = ndb.auth.LoadProvisionerByName(o.Name)
	case o.ID != "":
		prov, err = ndb.auth.LoadProvisionerByID(o.ID)
	default:
		return nil, errors.New("provisioner options must define either ID or Name to retrieve")
	}

	if err != nil {
		return nil, fmt.Errorf("error loading provisioner: %w", err)
	}

	linkedcaProv, err := authority.ProvisionerToLinkedca(prov)
	if err != nil {
		return nil, fmt.Errorf("error converting provisioner interface to linkedca provisioner: %w", err)
	}

	return linkedcaProv, nil
}

func (ndb *nodbCRUD) UpdateProvisioner(name string, prov *linkedca.Provisioner) error {
	if err := ndb.auth.UpdateProvisioner(ndb.ctx, prov); err != nil {
		return fmt.Errorf("error updating provisioner: %w", err)
	}

	if err := ndb.write(); err != nil {
		return err
	}

	return nil
}

func (ndb *nodbCRUD) RemoveProvisioner(opts ...ca.ProvisionerOption) error {
	o := new(ca.ProvisionerOptions)
	if err := o.Apply(opts); err != nil {
		return err
	}

	var (
		err  error
		prov provisioner.Interface
	)

	switch {
	case o.Name != "":
		prov, err = ndb.auth.LoadProvisionerByName(o.Name)
	case o.ID != "":
		prov, err = ndb.auth.LoadProvisionerByID(o.ID)
	default:
		return errors.New("provisioner options must define either ID or Name to remove")
	}

	if err != nil {
		return fmt.Errorf("error loading provisioner: %w", err)
	}

	if err := ndb.auth.RemoveProvisioner(ndb.ctx, prov.GetID()); err != nil {
		return fmt.Errorf("error removing provisioner: %w", err)
	}

	if err := ndb.write(); err != nil {
		return err
	}

	return nil
}

func (ndb *nodbCRUD) GetProvisioners(opts ...ca.ProvisionerOption) (provisioner.List, error) {
	o := new(ca.ProvisionerOptions)
	if err := o.Apply(opts); err != nil {
		return nil, err
	}

	if o.Limit == 0 {
		o.Limit = 100
	}

	var (
		cursor = o.Cursor
		limit  = o.Limit
		provs  = provisioner.List{}
	)
	for {
		page, nextCursor, err := ndb.auth.GetProvisioners(cursor, limit)
		if err != nil {
			return nil, err
		}
		provs = append(provs, page...)
		if nextCursor == "" {
			return provs, nil
		}
		cursor = nextCursor
	}
}

func (ndb *nodbCRUD) write() error {
	provs, err := ndb.GetProvisioners()
	if err != nil {
		return err
	}
	cfg := ndb.auth.GetConfig()
	cfg.AuthorityConfig.Provisioners = provs
	if err := cfg.Save(ndb.configFile); err != nil {
		return err
	}

	ui.Println("Success! Your `step-ca` config has been updated. To pick up the new configuration SIGHUP (kill -1 <pid>) or restart the step-ca process.")

	return nil
}
