terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
  }
}

variable "region_a_name" {
  type    = string
  default = "region-north-primary"
}

variable "region_b_name" {
  type    = string
  default = "region-south-secondary"
}

# Regional Namespaces
resource "kubernetes_namespace" "portal_ns_a" {
  metadata {
    name = "defence-cyber-portal"
    labels = {
      environment    = "production"
      region         = var.region_a_name
      workload_class = "critical-realtime"
    }
  }
}

resource "kubernetes_namespace" "eventbus_ns_a" {
  metadata {
    name = "eventbus"
    labels = {
      environment = "production"
      region      = var.region_a_name
    }
  }
}

# Network Policy for Regional Event Bus Isolation (Section 6.1)
resource "kubernetes_network_policy" "eventbus_policy" {
  metadata {
    name      = "eventbus-isolation"
    namespace = kubernetes_namespace.eventbus_ns_a.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "redpanda"
      }
    }

    ingress {
      from {
        namespace_selector {
          match_labels = {
            name = "defence-cyber-portal"
          }
        }
      }
      ports {
        port     = "9092"
        protocol = "TCP"
      }
    }

    policy_types = ["Ingress"]
  }
}
