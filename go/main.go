package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/robinbryce/authex/server"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	Name = "authex"
)

func main() {
	v := viper.New()
	cfg := server.NewConfig()
	setDefaultConfig(v, Name, cfg)

	f := pflag.NewFlagSet(Name, pflag.ContinueOnError)

	var cfgFile string
	f.StringVar(&cfgFile, "config", "", "configuration file. all options can be set in this")

	f.StringVar(
		&cfg.Address, "address", cfg.Address, `
	Listen address as host:port.
	`)

	f.StringVar(
		&cfg.Prefix, "prefix", cfg.Prefix, `
	Prefix all served routes with this value. A leading '/' is added to the path
	if absent. You must include trailing '/' if a full segment is intended
	`)

	f.DurationVar(
		&cfg.ShutdownGrace, "shutdown-grace", cfg.ShutdownGrace, `
	Server shutdown gace period.
	`)
	f.DurationVar(
		&cfg.WriteTimeout, "write-timout", cfg.WriteTimeout, `timeout for writes`)
	f.DurationVar(
		&cfg.ReadTimeout, "read-timeout", cfg.ReadTimeout, `timeout for reads`)
	f.DurationVar(
		&cfg.IdleTimeout, "idle-timeout", cfg.IdleTimeout, `idle timeout`)

	pflag.Parse()

	exitOnErr(setConfigFile(v, cfgFile, Name))

	if err := v.ReadInConfig(); err != nil {
		// It's okay if there isn't a config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			exitOnErr(err)
		}
	}

	v.SetEnvPrefix(strings.ToUpper(Name))
	v.AutomaticEnv()
	reconcileOptions(f, v, Name)

	s, err := server.NewServer(context.Background(), filepath.Dir(cfgFile), &cfg)
	exitOnErr(err)

	s.Serve()
}

func exitOnErr(err error) {
	if err == nil {
		return
	}
	fmt.Printf("error: %v\n", err)
}

func reconcileOptions(flags *pflag.FlagSet, v *viper.Viper, name string) {

	envPrefix := strings.ToUpper(strings.ReplaceAll(name, ".", "_"))

	flags.VisitAll(func(f *pflag.Flag) {

		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR

		envVar := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if len(envPrefix) > 0 {
			envVar = fmt.Sprintf("%s_%s", envPrefix, envVar)
		}

		fmt.Printf("bind env: %s -> %s\n", envVar, f.Name)
		v.BindEnv(f.Name, envVar)

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			fmt.Println("set:", f.Name, val)
			flags.Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}

func setDefaultConfig(v *viper.Viper, name string, cfg interface{}) error {
	marshaled, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var mapped map[string]interface{}
	if err := json.Unmarshal(marshaled, &mapped); err != nil {
		return err
	}
	v.SetDefault(name, mapped)
	return nil
}

func setConfigFile(v *viper.Viper, cfgFile, name string) error {
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		v.AddConfigPath(".")
		v.AddConfigPath(home)
		v.SetConfigName(name)
	}
	return nil
}
