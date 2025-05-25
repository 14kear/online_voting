package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
)

type Config struct {
	Env         string     `yaml:"env" env-default:"local"`
	StoragePath string     `yaml:"storage_path" env-required:"true"`
	GRPC        GRPCConfig `yaml:"grpc"`
	HTTP        HTTPConfig `yaml:"http"`
}

type GRPCConfig struct {
	Address string `yaml:"address"`
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
