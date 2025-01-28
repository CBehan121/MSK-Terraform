resource "aws_default_vpc" "default" {
}

resource "aws_default_subnet" "default_subnet" {
  for_each  = toset(var.availability_zones)
  availability_zone = each.value
}

output "subnet_ids" {
  value = [
    for v in aws_default_subnet.default_subnet : v.id
  ]
}

output "vpc_id" {
  value = aws_default_vpc.default.id
}