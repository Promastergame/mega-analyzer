import Config

# In production the port can be overridden from the environment so the same
# release can back several arenas behind a load balancer.
if config_env() == :prod do
  config :bit_arena,
    http_port: String.to_integer(System.get_env("BIT_ARENA_PORT") || "4000")
end
