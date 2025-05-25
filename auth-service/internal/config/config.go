package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
	"time"
)

type Config struct {
	Env             string        `yaml:"env" env-default:"local"`
	StoragePath     string        `yaml:"storage_path" env-required:"true"`
	GRPC            GRPCConfig    `yaml:"grpc"`
	HTTP            HTTPConfig    `yaml:"http"`
	AccessTokenTTL  time.Duration `yaml:"access_ttl" env-required:"true"`
	RefreshTokenTTL time.Duration `yaml:"refresh_ttl" env-required:"true"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}

type HTTPConfig struct {
	Port int `yaml:"port"`
}

func Load(path string) *Config {
	var config Config
	err := cleanenv.ReadConfig(path, &config)
	if err != nil {
		log.Fatalf("cannot read config: %s", err)
	}
	return &config
}
