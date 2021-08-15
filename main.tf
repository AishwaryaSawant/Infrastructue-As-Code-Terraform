provider "aws" {
  region = "${var.region}"
}

variable "region" {
  type = "string"
}

variable "cidr_block" {
  type = "string"
}

variable "subnet1_cidr_block" {
  type = "string"
}

variable "subnet2_cidr_block" {
  type = "string"
}

variable "subnet3_cidr_block" {
  type = "string"
}

variable "sub1availzone" {
  type = "string"
}

variable "sub2availzone" {
  type = "string"
}

variable "sub3availzone" {
  type = "string"
}
variable "vpctag" {
  type = "string"
}

variable "vpcNametag" {
  type = "string"
}

variable "subnet1tag" {
  type = "string"
}

variable "subnet2tag" {
  type = "string"
}

variable "subnet3tag" {
  type = "string"
}

variable "gwtag" {
  type = "string"
}

variable "rttag" {
  type = "string"
}

variable "ami_id" {
  type = "string"
}

variable "username" {
  type = "string"
}

variable "password" {
  type = "string"
}

variable "cicduser" {
  type = "string"
}

variable "GH-ec2-policy" {
  type = "string"
}

variable "prod_zone_id" {
  type = "string"
}

variable "prod_record_name" {
  type = "string"
}

# variable "cloudwatchagent_admin_policy" {
#   type = "string"
# }

variable "cloudwatchagent_server_policy" {
  type = "string"
}

# variable "dev_zone_id" {
#   type = "string"
# }

# variable "dev_record_name" {
#   type = "string"
# }
                

resource "aws_vpc" "csye6225_a4_vpc" {
  cidr_block                       = "${var.cidr_block}"
  enable_dns_hostnames             = true
  enable_dns_support               = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false

  tags = {
    Name   = "${var.vpcNametag}"
    NewTag = "${var.vpctag}"
  }
}

resource "aws_subnet" "subnet1" {
  cidr_block              = "${var.subnet1_cidr_block}"
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  availability_zone       = "${var.sub1availzone}"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.subnet1tag}"
  }
}

resource "aws_subnet" "subnet2" {
  cidr_block              = "${var.subnet2_cidr_block}"
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  availability_zone       = "${var.sub2availzone}"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.subnet2tag}"
  }
}

resource "aws_subnet" "subnet3" {
  cidr_block              = "${var.subnet3_cidr_block}"
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  availability_zone       = "${var.sub3availzone}"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.subnet3tag}"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.csye6225_a4_vpc.id}"

  tags = {
    Name = "${var.gwtag}"
  }
}

resource "aws_route_table" "rt" {
  vpc_id = "${aws_vpc.csye6225_a4_vpc.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.gw.id}"
  }

  tags = {
    Name = "${var.rttag}"
  }
}

resource "aws_route_table_association" "a1" {
  subnet_id      = "${aws_subnet.subnet1.id}"
  route_table_id = "${aws_route_table.rt.id}"
}

resource "aws_route_table_association" "a2" {
  subnet_id      = "${aws_subnet.subnet2.id}"
  route_table_id = "${aws_route_table.rt.id}"
}

resource "aws_route_table_association" "a3" {
  subnet_id      = "${aws_subnet.subnet3.id}"
  route_table_id = "${aws_route_table.rt.id}"
}

variable "app_sec_group" {
  type = "string"
}

resource "aws_security_group" "application" {
  name        = "${var.app_sec_group}"
  description = "Security group for webapp"
  vpc_id      = "${aws_vpc.csye6225_a4_vpc.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    # cidr_blocks = ["0.0.0.0/0"]
    security_groups = ["${aws_security_group.lb.id}"]
  }

  # ingress {
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  #   security_groups = ["${aws_security_group.lb.id}"]
  # }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    # cidr_blocks = ["0.0.0.0/0"]
    security_groups = ["${aws_security_group.lb.id}"]
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    # cidr_blocks = ["0.0.0.0/0"]
    security_groups = ["${aws_security_group.lb.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "db_sec_group" {
  type = "string"
}

resource "aws_security_group" "database" {
  name        = "${var.db_sec_group}"
  description = "Security group for RDS instance"
  vpc_id      = "${aws_vpc.csye6225_a4_vpc.id}"

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = ["${aws_security_group.application.id}"]
  }
}

variable "webapp_bucket" {
  type = "string"
}

resource "aws_s3_bucket" "bucket" {
  bucket        = "${var.webapp_bucket}"
  acl           = "private"
  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    id      = "move"
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

variable "dbsubnet_name" {
  type = "string"
}

resource "aws_db_subnet_group" "dbsubnet" {
  name       = "${var.dbsubnet_name}"
  subnet_ids = ["${aws_subnet.subnet1.id}", "${aws_subnet.subnet2.id}", "${aws_subnet.subnet3.id}"]
}

variable "db_identifier" {
  type = "string"
}

variable "db_name" {
  type = "string"
}

resource "aws_db_instance" "csye6225-f20" {
  allocated_storage      = 20
  engine                 = "mysql"
  engine_version         = "8.0.17"
  instance_class         = "db.t3.micro"
  multi_az               = "false"
  identifier             = "${var.db_identifier}"
  username               = "${var.username}"
  password               = "${var.password}"
  name                   = "${var.db_name}"
  db_subnet_group_name   = "${aws_db_subnet_group.dbsubnet.name}"
  publicly_accessible    = "false"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  skip_final_snapshot    = true
  storage_encrypted      = true
  parameter_group_name   = "${aws_db_parameter_group.enforcessl.name}"
}

resource "aws_db_parameter_group" "enforcessl" {
  name   = "enforcessl"
  family = "mysql8.0"

  parameter {
    apply_method = "pending-reboot"
    name  = "performance_schema"
    value = "1"
  }
}

variable "iam_ec2_profile_name" {
  type = "string"
}

resource "aws_iam_instance_profile" "iam_ec2_profile" {
  name = "${var.iam_ec2_profile_name}"
  role = "${aws_iam_role.role.name}"
}

# resource "aws_instance" "web" {
#   ami                     = "${var.ami_id}"
#   instance_type           = "t2.micro"
#   disable_api_termination = "false"
#   associate_public_ip_address = true
#   subnet_id               = "${aws_subnet.subnet1.id}"
#   vpc_security_group_ids  = ["${aws_security_group.application.id}"]
#   depends_on              = [aws_db_instance.csye6225-f20]
#   key_name                = "csye6225"
#   iam_instance_profile    = "${aws_iam_instance_profile.iam_ec2_profile.name}"
#   root_block_device {
#     volume_size           = 20
#     volume_type           = "gp2"
#     delete_on_termination = "true"
#   }
#   user_data = <<-EOFL
# #!/bin/bash
# sudo mkdir /home/ubuntu/config
#   cat > /home/ubuntu/config/config.json << EOF
# {
# "development": {
#     "username": "${aws_db_instance.csye6225-f20.username}",
#     "password": "${aws_db_instance.csye6225-f20.password}",
#     "database": "${aws_db_instance.csye6225-f20.name}",
#     "host": "${aws_db_instance.csye6225-f20.address}",
#     "dialect": "mysql",
#     "operatorsAliases": false,
#     "s3_bucket": "${aws_s3_bucket.bucket.bucket}",
#     "region": "${var.region}"
#   }
# }
# EOF
# EOFL

#   tags = {
#     Name   = "EC2 Terraform"
#     deploy = "EC2 Codedeploy"
#   }
# }

variable "dynamodb_name" {
  type = "string"
}

resource "aws_dynamodb_table" "csye6225" {
  name           = "${var.dynamodb_name}"
  hash_key       = "answerid"
  read_capacity  = 20
  write_capacity = 20

  attribute {
    name = "answerid"
    type = "S"
  }

  # ttl {
  #   attribute_name = "TimeToExist"
  #   enabled        = true
  # }
}

variable "webappS3_policy" {
  type = "string"
}

resource "aws_iam_policy" "policy" {
  name        = "${var.webappS3_policy}"
  description = "EC2 S3 policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:GetObjectAcl",
        "s3:DeleteObject"
      ],
      "Effect": "Allow",
      "Resource": [
                "arn:aws:s3:::${var.webapp_bucket}",
                "arn:aws:s3:::${var.webapp_bucket}/*"
            ]
    }
  ]
}
EOF
}



variable "EC2-CSYE6225_role" {
  type = "string"
}

resource "aws_iam_role" "role" {
  name = "${var.EC2-CSYE6225_role}"

  assume_role_policy = <<EOF
{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Principal": {
            "Service": "ec2.amazonaws.com"
          },
          "Effect": "Allow",
          "Sid": ""
        }
      ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ec2-s3-attach" {
  role       = "${aws_iam_role.role.name}"
  policy_arn = "${aws_iam_policy.policy.arn}"
}

resource "aws_iam_role_policy_attachment" "codedeploy-ec2-s3-attach" {
  role       = "${aws_iam_role.role.name}"
  policy_arn = "${aws_iam_policy.policy1.arn}"
}


resource "aws_iam_role_policy_attachment" "cloudwatch-ec2-attach" {
  role       = "${aws_iam_role.role.name}"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "ec2-sns-attach" {
  role       = "${aws_iam_role.role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}



variable "codedeploy_bucket" {
  type = "string"
}

variable "CodeDeploy-EC2-S3_policy1" {
  type = "string"
}

resource "aws_iam_policy" "policy1" {
  name        = "${var.CodeDeploy-EC2-S3_policy1}"
  description = "This policy allows EC2 instances to read data from S3 buckets"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
              "s3:GetObject",
              "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": [
                "arn:aws:s3:::${var.codedeploy_bucket}",
                "arn:aws:s3:::${var.codedeploy_bucket}/*"
            ]
    }
  ]
}
EOF
}


variable "CodeDeployEC2ServiceRole_role1" {
  type = "string"
}

resource "aws_iam_role" "role1" {
  name               = "${var.CodeDeployEC2ServiceRole_role1}"
  description        = "Allows EC2 instances to call AWS services on your behalf"
  assume_role_policy = <<EOF
{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          
          "Principal": {
            "Service": "ec2.amazonaws.com"
          },
          "Effect": "Allow",
          "Sid": ""
        }
      ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "CodeDeployEC2Service-attach" {
  role       = "${aws_iam_role.role1.name}"
  policy_arn = "${aws_iam_policy.policy1.arn}"
}

variable "GH-Upload-To-S3_policy2" {
  type = "string"
}

resource "aws_iam_policy" "policy2" {
  name        = "${var.GH-Upload-To-S3_policy2}"
  description = "This policy allows GH actions to upload artifacts from latest successful build to dedicated S3 bucket"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": [
                "arn:aws:s3:::${var.codedeploy_bucket}",
                "arn:aws:s3:::${var.codedeploy_bucket}/*"
            ]
    }
  ]
}
EOF
}

variable "CodeDeployServiceRole_role2" {
  type = "string"
}

resource "aws_iam_role" "role2" {
  name               = "${var.CodeDeployServiceRole_role2}"
  description        = "Allows EC2 instances to call AWS services on your behalf"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}


resource "aws_iam_role_policy_attachment" "codedeploy-attach" {
  role       = "${aws_iam_role.role2.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}

variable "GH-Code-Deploy_policy3" {
  type = "string"
}

variable "AWS_account_num" {
  type = "string"
}

resource "aws_iam_policy" "policy3" {
  name        = "${var.GH-Code-Deploy_policy3}"
  description = "This policy allows allows GH actions to call CodeDeploy APIs to initiate application deployment on EC2 instances"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.AWS_account_num}:application:${var.codedeploy_app_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
       "arn:aws:codedeploy:${var.region}:${var.AWS_account_num}:deploymentgroup:${var.codedeploy_app_name}/${var.codedeploy_group_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.AWS_account_num}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${var.AWS_account_num}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${var.AWS_account_num}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "cicduser-attach-1" {
  user       = "${var.cicduser}"
  policy_arn = "${aws_iam_policy.policy2.arn}"
}

resource "aws_iam_user_policy_attachment" "cicduser-attach-2" {
  user       = "${var.cicduser}"
  policy_arn = "${aws_iam_policy.policy3.arn}"
}


resource "aws_iam_user_policy_attachment" "cicduser-attach3" {
  user       = "${var.cicduser}"
  policy_arn = "${var.GH-ec2-policy}"
}


# resource "aws_iam_user_policy_attachment" "cicduser-attach4" {
#   user       = "${var.cicduser}"
#   policy_arn = "${var.cloudwatchagent_admin_policy}"
# }


resource "aws_iam_user_policy_attachment" "cicduser-attach5" {
  user       = "${var.cicduser}"
  policy_arn = "${var.cloudwatchagent_server_policy}"
}

resource "aws_iam_user_policy_attachment" "cicduser-attach-4" {
  user       = "${var.cicduser}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}

variable "codedeploy_app_name" {
  type = "string"
}

resource "aws_codedeploy_app" "csye6225-webapp" {
  compute_platform = "Server"
  name             = "${var.codedeploy_app_name}"
}

variable "codedeploy_group_name" {
  type = "string"
}

resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name               = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name  = "${var.codedeploy_group_name}"
  service_role_arn       = "${aws_iam_role.role2.arn}"
  autoscaling_groups     = ["${aws_autoscaling_group.asg.name}"]
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  deployment_style {
    deployment_type = "IN_PLACE"
  }
  ec2_tag_set {
    ec2_tag_filter {
      key   = "deploy"
      type  = "KEY_AND_VALUE"
      value = "EC2 Codedeploy"
    }
  }
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}

# resource "aws_route53_record" "prod" {
#   zone_id = "${var.prod_zone_id}"
#   name    = "${var.prod_record_name}"
#   type    = "A"
#   ttl     = "36000"
#   records = ["${aws_instance.web.public_ip}"]
# }

# resource "aws_route53_record" "www" {    --a7
#   zone_id = "Z07197682NF02XT9FYF9Z"
#   name    = "api.prod.aishwaryas.me"
#   type    = "A"
#   ttl     = "3600"
#     records = ["${aws_instance.web.public_ip}"]

# }

# resource "aws_route53_record" "dev" {
#   zone_id = "${var.dev_zone_id}"
#   name    = "${var.dev_record_name}"
#   type    = "A"
#   ttl     = "60"
#   records = ["${aws_instance.web.public_ip}"]
# }


resource "aws_launch_configuration" "as_conf" {
  name          = "asg_launch_config"
  image_id      = "${var.ami_id}"
  instance_type = "t2.micro"
  depends_on    = [aws_db_instance.csye6225-f20]
  key_name      = "csye6225"
  associate_public_ip_address = true
  iam_instance_profile    = "${aws_iam_instance_profile.iam_ec2_profile.name}"
  security_groups  = ["${aws_security_group.application.id}"]
  root_block_device {
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = "true"
  }
  user_data = <<-EOFL
  #!/bin/bash
  sudo mkdir /home/ubuntu/config
    cat > /home/ubuntu/config/config.json << EOF
  {
  "development": {
      "username": "${aws_db_instance.csye6225-f20.username}",
      "password": "${aws_db_instance.csye6225-f20.password}",
      "database": "${aws_db_instance.csye6225-f20.name}",
      "host": "${aws_db_instance.csye6225-f20.address}",
      "dialect": "mysql",
      "operatorsAliases": false,
      "s3_bucket": "${aws_s3_bucket.bucket.bucket}",
      "region": "${var.region}"
    }
  }
  EOF
  EOFL

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "asg" {
  name                 = "webapp_asg"
  default_cooldown = 60
  launch_configuration = "${aws_launch_configuration.as_conf.name}"
  min_size             = 3
  max_size             = 5
  desired_capacity     = 3
  vpc_zone_identifier       = ["${aws_subnet.subnet1.id}"]

  lifecycle {
    create_before_destroy = true
  }

  tag {
    key                 = "deploy"
    value               = "EC2 Codedeploy"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "ScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
}

resource "aws_autoscaling_policy" "ScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  alarm_name          = "CPUAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "5"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.asg.name}"
  }

  alarm_description = "Scale-up if CPU > 5% for 1 minute"
  alarm_actions     = ["${aws_autoscaling_policy.ScaleUpPolicy.arn}"]
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_name          = "CPUAlarmLow"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "3"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.asg.name}"
  }

  alarm_description = "Scale-down if CPU < 3% for 1 minute"
  alarm_actions     = ["${aws_autoscaling_policy.ScaleDownPolicy.arn}"]
}

resource "aws_lb" "app_lb" {
  name               = "webapp-lb"
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.lb.id}"]
  subnets            = ["${aws_subnet.subnet1.id}","${aws_subnet.subnet2.id}"]
}

resource "aws_security_group" "lb" {
  name        = "lb"
  description = "Security group for load balancer"
  vpc_id      = "${aws_vpc.csye6225_a4_vpc.id}"
  # ingress {
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# resource "aws_lb_listener" "lb_listener" {
#   load_balancer_arn = "${aws_lb.app_lb.arn}"
#   port              = "80"
#   protocol          = "HTTP"

#   default_action {
#     type             = "forward"
#     target_group_arn = "${aws_lb_target_group.tg.arn}"
#   }
# }
resource "aws_lb_listener" "lb_listener" {
  load_balancer_arn = "${aws_lb.app_lb.arn}"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:663668038035:certificate/0d6541c0-f992-4e81-baea-e5041c03376c"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.tg.arn}"
  }
}

resource "aws_lb_target_group" "tg" {
  name     = "webapp-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.csye6225_a4_vpc.id}"
  stickiness {    
    type            = "lb_cookie"    
    cookie_duration = 1800    
    enabled         = true 
  }

  health_check {
    interval    = 20
    path        = "/"
    port        = "3000"
    protocol = "HTTP"
    timeout = 15
    healthy_threshold = 2
    unhealthy_threshold = 3
    matcher = "200,201"
  }
}

resource "aws_autoscaling_attachment" "asg_attachment_bar" {
  autoscaling_group_name = "${aws_autoscaling_group.asg.id}"
  alb_target_group_arn   = "${aws_lb_target_group.tg.arn}"
}

resource "aws_route53_record" "www" {
  zone_id = "Z0107241NT4WIKUIL5RW"
  # name    = "api.prods.aishwaryas.me"
  name = "prods.aishwaryas.me"
  type    = "A"
  alias {
    name                   = "${aws_lb.app_lb.dns_name}"
    zone_id                = "${aws_lb.app_lb.zone_id}"
    evaluate_target_health = true
  }
}

resource "aws_sns_topic" "answer_events" {
  name = "answer_events"
}

resource "aws_iam_role" "lambda-sns-role" {
  name = "lambda-sns-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "sesPolicy" {
  name        = "sesPolicy"
  description = "SES policy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "basic-exec-role" {
  role       = "${aws_iam_role.lambda-sns-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "dynamodb-lambda" {
  role       = "${aws_iam_role.lambda-sns-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "ses-attach" {
  role       = "${aws_iam_role.lambda-sns-role.name}"
  policy_arn = "${aws_iam_policy.sesPolicy.arn}"
}

resource "aws_lambda_function" "lambda" {
  filename         = "lambdafunction.zip"
  function_name    = "lambda-handler"
  role             = "${aws_iam_role.lambda-sns-role.arn}"
  handler          = "index.handler"
  runtime          = "nodejs12.x"
} 

resource "aws_sns_topic_subscription" "topic_lambda" {
  topic_arn = "${aws_sns_topic.answer_events.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.lambda.arn}"
}

resource "aws_lambda_permission" "with_sns" {
    statement_id = "AllowExecutionFromSNS"
    action = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda.arn}"
    principal = "sns.amazonaws.com"
    source_arn = "${aws_sns_topic.answer_events.arn}"
}