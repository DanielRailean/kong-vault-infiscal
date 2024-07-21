return {
  name = "infiscal",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          {
            ttl = {
              type = "number",
              default = 60 * 60,
              required = true
            }
          },
          -- {
          --   neg_ttl = {
          --     type = "number",
          --     default = 0,
          --     required = true
          --   },
          -- },
          -- {
          --   resurrect_ttl = {
          --     type = "number",
          --     default = 24 * 60 * 60,
          --     required = true
          --   }
          -- },
          -- {
          --   min_ttl = {
          --     type = "number",
          --     default = 5,
          --     required = true
          --   }
          -- },
          -- {
          --   max_ttl = {
          --     type = "number",
          --     default = 10,
          --     required = true
          --   }
          -- },
          {
            connection = {
              type = "record",
              fields = {
                {
                  base_url = {
                    type = "string",
                    required = true,
                    default = "https://app.infisical.com"
                  },
                },
                {
                  timeouts = {
                    type = "record",
                    fields = {
                      {
                        auth = {
                          type = "number",
                          required = true,
                          default = 3000,
                          between = { 10, 10000 }
                        }
                      },
                      {
                        get = {
                          type = "number",
                          required = true,
                          default = 2000,
                          between = { 10, 10000 }
                        }
                      },
                    }
                  }
                },
              }
            }
          },
          {
            auth = {
              type = "record",
              description =
              "the values go to the body of the call to https://infisical.com/docs/api-reference/endpoints/universal-auth/login",
              fields = {
                {
                  clientId = {
                    type = "string",
                    required = true
                  }
                },
                {
                  clientSecret = {
                    type = "string",
                    required = true
                  }
                },
              }
            }
          },
          {
            query = {
              type = "record",
              description =
              "the values go directly to the https://infisical.com/docs/api-reference/endpoints/secrets/read query",
              fields = {
                {
                  workspaceId = {
                    type = "string",
                    required = false
                  }
                },
                {
                  workspaceSlug = {
                    type = "string",
                    required = false
                  }
                },
                {
                  environment = {
                    type = "string",
                    required = false
                  }
                },
                {
                  secretPath = {
                    type = "string",
                    required = false
                  }
                },
                {
                  version = {
                    type = "number",
                    required = false
                  }
                },
                {
                  type = {
                    type = "string",
                    one_of = { "shared", "personal" },
                    required = false
                  }
                },
                {
                  expandSecretReferences = {
                    type = "boolean",
                    required = false
                  }
                },
                {
                  include_imports = {
                    type = "boolean",
                    required = false
                  }
                }
              }
            }
          },
        },
      },
    },
  },
}
