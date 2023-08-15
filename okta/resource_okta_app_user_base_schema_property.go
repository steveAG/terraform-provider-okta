package okta

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAppUserBaseSchemaProperty() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAppUserBaseSchemaCreate,
		ReadContext:   resourceAppUserBaseSchemaRead,
		UpdateContext: resourceAppUserBaseSchemaUpdate,
		DeleteContext: resourceFuncNoOp,
		Importer:      createNestedResourceImporter([]string{"app_id", "index"}),
		Schema: buildSchema(
			userBaseSchemaSchema,
			userTypeSchema,
			userPatternSchema,
			map[string]*schema.Schema{
				"app_id": {
					Type:     schema.TypeString,
					Required: true,
				},
				"master": {
					Type:     schema.TypeString,
					Optional: true,
					// Accepting an empty value to allow for zero value (when provisioning is off)
					Description: "SubSchema profile manager, if not set it will inherit its setting.",
					Default:     "PROFILE_MASTER",
				},
				"scope": {
					Type:     schema.TypeString,
					Optional: true,
					Default:  "NONE",
					ForceNew: true, // since the `scope` is read-only attribute, the resource should be recreated
				},
				"union": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "Allows to assign attribute's group priority",
					Default:     false,
				},
			}),
		SchemaVersion: 1,
		StateUpgraders: []schema.StateUpgrader{
			{
				Type: resourceAppUserBaseSchemaResourceV0().CoreConfigSchema().ImpliedType(),
				Upgrade: func(ctx context.Context, rawState map[string]interface{}, meta interface{}) (map[string]interface{}, error) {
					rawState["user_type"] = "default"
					return rawState, nil
				},
				Version: 0,
			},
		},
	}
}

func resourceAppUserBaseSchemaResourceV0() *schema.Resource {
	return &schema.Resource{Schema: buildSchema(map[string]*schema.Schema{
		"app_id": {
			Type:     schema.TypeString,
			Required: true,
		},
		"scope": {
			Type:     schema.TypeString,
			Optional: true,
			Default:  "NONE",
			ForceNew: true, // since the `scope` is read-only attribute, the resource should be recreated
		},
	}, userBaseSchemaSchema)}
}

func resourceAppUserBaseSchemaCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if err := updateAppUserBaseSubschema(ctx, d, m); err != nil {
		return err
	}
	d.SetId(fmt.Sprintf("%s/%s", d.Get("app_id").(string), d.Get("index").(string)))
	return resourceAppUserBaseSchemaRead(ctx, d, m)
}

func resourceAppUserBaseSchemaRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	us, _, err := getOktaClientFromMetadata(m).UserSchema.GetApplicationUserSchema(ctx, d.Get("app_id").(string))
	if err != nil {
		return diag.Errorf("failed to get app user base schema: %v", err)
	}
	subschema := userSchemaBaseAttribute(us, d.Get("index").(string))
	if subschema == nil {
		d.SetId("")
		return nil
	}
	syncBaseUserSchema(d, subschema)
	if subschema.Union != "" {
		if subschema.Union == "DISABLE" {
			_ = d.Set("union", false)
		} else {
			_ = d.Set("union", true)
		}
	}
	return nil
}

func resourceAppUserBaseSchemaUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if err := updateAppUserBaseSubschema(ctx, d, m); err != nil {
		return err
	}
	return resourceAppUserBaseSchemaRead(ctx, d, m)
}

// create or modify a subschema
func updateAppUserBaseSubschema(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	err := validateAppUserBaseSchema(d)
	if err != nil {
		return diag.FromErr(err)
	}
	base := buildBaseUserSchema(d)
	url := fmt.Sprintf("/api/v1/meta/schemas/apps/%v/default", d.Get("app_id").(string))
	re := getOktaClientFromMetadata(m).GetRequestExecutor()
	req, err := re.WithAccept("application/json").WithContentType("application/json").
		NewRequest("POST", url, base)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = re.Do(ctx, req, nil)
	if err != nil {
		return diag.Errorf("failed to update application user base schema: %v", err)
	}
	return nil
}

func validateAppUserBaseSchema(d *schema.ResourceData) error {
	_, ok := d.GetOk("pattern")
	if d.Get("index").(string) != "login" {
		if ok {
			return fmt.Errorf("'pattern' property is only allowed to be set for 'login'")
		}
		return nil
	} else {
		if !d.Get("required").(bool) {
			return fmt.Errorf("'login' base schema is always required attribute")
		}
	}

	if scope, ok := d.GetOk("scope"); ok {
		if union, ok := d.GetOk("union"); ok {
			if scope == "SELF" && union.(bool) {
				return errors.New("you can not use combine values across groups (union=true) for self scoped " +
					"attribute (scope=SELF). Either change scope to 'NONE', or use group priority option by setting union to 'false'")
			}
		}
	}

	return nil
}
