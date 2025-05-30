package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/constant-mihai/xdp-loadbalancer-prototype/pkg/bpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	GitCommit          string
	GitBranch          string
	ApplicationVersion string
)

type Config struct {
	Logging struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"logging"`

	Metrics struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"metrics"`

	Dataplane bpf.Config `mapstructure:"dataplane"`
}

var (
	xlbpVersion = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "xlbp",
			Name:      "application_version",
			Help:      "Xlbp version",
		},
		[]string{"Commit", "Branch", "ApplicationVersion"},
	)
)

type Xlbp struct {
	config     *Config
	logger     *zap.Logger
	metrics    *http.Server
	wg         sync.WaitGroup
	dataplane  *bpf.Dataplane
	inShutdown atomic.Bool // true when server is in shutdown
}

func NewApplication() (*Xlbp, error) {
	xlbp := &Xlbp{}

	if err := xlbp.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if err := xlbp.initLogger(); err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	if err := xlbp.initServers(); err != nil {
		return nil, fmt.Errorf("failed to initialize servers: %w", err)
	}

	var err error
	if xlbp.dataplane, err = bpf.LoadDataplane(xlbp.config.Dataplane, xlbp.logger); err != nil {
		return nil, fmt.Errorf("failed to initialize the dataplane: %w", err)
	}

	return xlbp, nil
}

func (xlbp *Xlbp) loadConfig() error {
	xlbp.config = &Config{}

	// Set config file
	viper.SetConfigName("xlbp")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/xlbp/")

	// Set defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")

	// Enable environment variables
	viper.SetEnvPrefix("XLBP")
	viper.AutomaticEnv()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		// Config file not found; use defaults and env vars
	}

	// Unmarshal config
	if err := viper.Unmarshal(xlbp.config); err != nil {
		return err
	}

	return nil
}

func (xlbp *Xlbp) initServers() error {
	xlbp.metrics = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", xlbp.config.Metrics.Host, xlbp.config.Metrics.Port),
		Handler: promhttp.Handler(),
	}

	return nil
}

// initLogger initializes the zap logger
func (xlbp *Xlbp) initLogger() error {
	var config zap.Config

	if xlbp.config.Logging.Format == "json" {
		config = zap.NewProductionConfig()
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Set log level
	level, err := zapcore.ParseLevel(xlbp.config.Logging.Level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	config.Level = zap.NewAtomicLevelAt(level)

	// Build logger
	logger, err := config.Build()
	if err != nil {
		return err
	}

	xlbp.logger = logger
	return nil
}

func (xlbp *Xlbp) Start() error {
	xlbp.logger.Info("starting application")
	xlbp.inShutdown.Store(false)
	xlbpVersion.WithLabelValues(GitCommit, GitBranch, ApplicationVersion).Set(1)

	xlbp.wg.Add(1)
	go func() {
		defer xlbp.wg.Done()
		xlbp.logger.Info("starting metrics server",
			zap.String("address", xlbp.metrics.Addr),
		)
		if err := xlbp.metrics.ListenAndServe(); err != http.ErrServerClosed {
			xlbp.logger.Fatal("metrics server error", zap.Error(err))
		}
	}()

	if err := xlbp.dataplane.Start(); err != nil {
		return fmt.Errorf("error starting the dataplane: %w", err)
	}

	return nil
}

func (xlbp *Xlbp) Shutdown(ctx context.Context) error {
	xlbp.logger.Info("shutting down application")
	xlbp.inShutdown.Store(true)

	if err := xlbp.metrics.Shutdown(ctx); err != nil {
		xlbp.logger.Error("error shutting down metrics server", zap.Error(err))
		return err
	}
	xlbp.wg.Wait()

	if err := xlbp.dataplane.Close(); err != nil {
		return err
	}

	return nil
}

func main() {
	xlbp, err := NewApplication()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create application: %v\n", err)
		os.Exit(1)
	}

	if err := xlbp.Start(); err != nil {
		xlbp.logger.Fatal("failed to start application", zap.Error(err))
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	xlbp.logger.Info("received signal", zap.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := xlbp.Shutdown(ctx); err != nil {
		xlbp.logger.Error("shutdown error", zap.Error(err))
		os.Exit(1)
	}

	xlbp.logger.Info("shutdown complete")
}
