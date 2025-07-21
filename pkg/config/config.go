package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

func LoadEnvVar() (EnvVar, error) {
	var c EnvVar
	if err := envconfig.Process("", &c); err != nil {
		return c, fmt.Errorf("failed to load environment variables: %w", err)
	}
	return c, nil
}

// HACK: while working with static usage
func LoadEnvVarFile() (EnvVar, error) {
	var env map[string]string
	env, err := godotenv.Read("./config/workflow.env")
	if err != nil {
		return EnvVar{}, fmt.Errorf("failed to read workflow.env file: %w", err)
	}

	ev := EnvVar{
		ServerConfig:   env["SERVER_CONFIG"],
		ServerPort:     env["SERVER_PORT"],
		ServerHost:     env["SERVER_HOST"],
		LoginConfig:    env["LOGIN_CONFIG"],
		LoginPort:      env["LOGIN_PORT"],
		LoginHost:      env["LOGIN_HOST"],
		AuthCodeConfig: env["AUTHCODE_CONFIG"],
		AuthCodePort:   env["AUTHCODE_PORT"],
		AuthCodeHost:   env["AUTHCODE_HOST"],
		PKCEConfig:     env["PKCE_CONFIG"],
		PKCEPort:       env["PKCE_PORT"],
		PKCEHost:       env["PKCE_HOST"],
	}

	return ev, nil
}

// Is there a better way to do this?
type EnvVar struct {
	ServerConfig   string `envconfig:"SERVER_CONFIG" default:"/app/config/config.yaml"`
	ServerPort     string `envconfig:"SERVER_PORT" default:":8082"`
	ServerHost     string `envconfig:"SERVER_HOST" default:""`
	LoginConfig    string `envconfig:"LOGIN_CONFIG" default:"/app/config/config.yaml"`
	LoginPort      string `envconfig:"LOGIN_PORT" default:":8080"`
	LoginHost      string `envconfig:"LOGIN_HOST" default:""`
	AuthCodeConfig string `envconfig:"AUTHCODE_CONFIG" default:"/app/config/config.yaml"`
	AuthCodePort   string `envconfig:"AUTHCODE_PORT" default:":8081"`
	AuthCodeHost   string `envconfig:"AUTHCODE_HOST" default:""`
	PKCEConfig     string `envconfig:"PKCE_CONFIG" default:"/app/config/config.yaml"`
	PKCEPort       string `envconfig:"PKCE_PORT" default:":8081"`
	PKCEHost       string `envconfig:"PKCE_HOST" default:""`
}

func LoadYAMLDocument[T any](path string) (*T, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("given filepath does not contain config: %w", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return GetConfig[T](bytes.NewReader(b))
}

func GetConfig[T any](reader io.Reader) (*T, error) {
	var cfg T
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("the config content is malformed: %w", err)
	}

	return &cfg, nil
}
