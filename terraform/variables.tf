variable "aws_region" {
  default = "ap-south-1"    # Mumbai — closest to Mohali
}

variable "project" {
  default = "threat-intel"
}

variable "ami_id" {
  # Ubuntu 22.04 LTS in ap-south-1 (Mumbai)
  # Check latest: https://cloud-images.ubuntu.com/locator/ec2/
  default = "ami-0aa761682283b4cc8"
}

variable "my_ip" {
  description = "Your home IP/32 for SSH access. Find it at https://checkip.amazonaws.com"
  type        = string
  # set this in terraform.tfvars
}

variable "public_key_path" {
  description = "Path to your SSH public key"
  default     = "~/.ssh/threat-intel.pub"
}
