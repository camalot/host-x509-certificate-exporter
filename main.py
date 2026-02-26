# Copyright 2022 Ryan Conrad

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



from cryptography import x509
from prometheus_client import start_http_server, Gauge, Enum
import codecs
import signal
import ssl
import pytz
import yaml
import re
import os
import time
from dotenv import load_dotenv, find_dotenv
import datetime

load_dotenv(find_dotenv())

class AppConfig():
	def __init__(self, file: str):
		# set defaults for config from environment variables if they exist
		self.metrics = {
			"port": int(dict_get(os.environ, "X509_CONFIG_METRICS_PORT", "8932")),
			"pollingInterval": int(dict_get(os.environ, "X509_CONFIG_METRICS_POLLING_INTERVAL", "43200"))
		}
		self.hosts = list()
		self.labels = list()

		try:
			# check if file exists
			if os.path.exists(file):
				print(f"Loading config from {file}")
				with codecs.open(file, encoding="utf-8-sig", mode="r") as f:
					settings = yaml.safe_load(f)
					self.__dict__.update(settings)
		except yaml.YAMLError as exc:
			print(exc)

		env_hosts = self.find_hosts_from_environment()
		if len(env_hosts) > 0:
			# merge env_hosts with config file
			self.hosts = self.hosts + env_hosts
			print(f"Appended {len(env_hosts)} hosts from environment variables")
		env_labels = self.find_labels_from_environment()
		if len(env_labels) > 0:
			# merge env_labels with config file
			for label in env_labels:
				# check if label already exists
				if label['name'] not in [x['name'] for x in self.labels]:
					print(f"adding label {label['name']} from environment variables")
					self.labels.append(label)
			print(f"Appended {len(env_labels)} labels from environment variables")

	def find_labels_from_environment(self):
		labels = list()
		for env in os.environ:
			pattern = r"^X509_CONFIG_LABEL_([A-Z0-9_-]+)$"
			if re.match(pattern, env, re.IGNORECASE | re.DOTALL):
				print(f"Found Label from Environment Variable: {env}")
				# get the capture group
				label = re.search(pattern, env, re.IGNORECASE | re.DOTALL).group(1)
				# get the value
				value = os.environ[env]
				# add to labels
				labels.append({
					"name": label.lower(),
					"value": value
				})
		return labels

	def find_hosts_from_environment(self):
		hosts = []
		for env in os.environ:
			if re.match(r"^X509_CONFIG_HOST_\d{1,}$", env, re.IGNORECASE | re.DOTALL):
				print(f"Found Host from Environment Variable: {env}")
				# split value by :
				values = os.environ[env].split(":")
				# check if we have 2 values
				if len(values) == 2:
					# add to hosts
					hosts.append({
						"name": values[0],
						"port": values[1]
					})
		return hosts

class X509Metrics:
	def __init__(self, config):
			self.namespace = "x509"
			self.polling_interval_seconds = config.metrics['pollingInterval']
			self.config = config
			labels = [
				"host",
				"issuer_C",
				"issuer_L",
				"issuer_O",
				"issuer_OU",
				"issuer_ST",
				"issuer_CN",
				"serial_number",
				"subject_C",
				"subject_L",
				"subject_O",
				"subject_OU",
				"subject_CN",
				"subject_ST"
			]
			# merge labels and config labels
			labels = labels + [x['name'] for x in self.config.labels]

			self.not_valid_after = Gauge(namespace=self.namespace, name=f"cert_not_after", documentation="The timestamp of when the certificate will expire", labelnames=labels)
			self.not_valid_before = Gauge(namespace=self.namespace, name=f"cert_not_before", documentation="The timestamp of when the certificate was issued", labelnames=labels)
			# if expired, set to 1, else 0
			self.expired = Gauge(namespace=self.namespace, name=f"expired", documentation="Indicates if the certificate is currently expired", labelnames=labels)
			self.host_read_errors = Gauge(namespace=self.namespace, name=f"host_read_errors", documentation="Indicates if there was an error reading the certificate", labelnames=["host"])
			self.read_errors = Gauge(namespace=self.namespace, name=f"read_errors", documentation="Indicates if there was an error reading the certificate")
			self.build_info = Gauge(namespace=self.namespace, name=f"build_info", documentation="A metric with a constant '1' value labeled with version", labelnames=["version", "ref", "build_date", "sha"])
			ver = dict_get(os.environ, "APP_VERSION", "1.0.0-snapshot")
			ref = dict_get(os.environ, "APP_BUILD_REF", "unknown")
			build_date = dict_get(os.environ, "APP_BUILD_DATE", "unknown")
			sha = dict_get(os.environ, "APP_BUILD_SHA", "unknown")
			self.build_info.labels(version=ver, ref=ref, build_date=build_date, sha=sha).set(1)
			
	def run_metrics_loop(self):
		"""Metrics fetching loop"""
		while True:
			print(f"begin metrics fetch")
			self.fetch()
			time.sleep(self.polling_interval_seconds)

	def get_oid_attribute(self, nameObject, oid):
		if nameObject.get_attributes_for_oid(oid):
			return nameObject.get_attributes_for_oid(oid)[0].value
		return None

	def fetch(self):
		hosts = self.config.hosts
		error_count = 0
		# loop hosts
		for host in hosts:
			try:
				# get host certificate
				cert = ssl.get_server_certificate((host['name'], host['port']))
				# parse certificate
				x509_cert = x509.load_pem_x509_certificate(cert.encode())
				# get expiration date
				expiration_date = x509_cert.not_valid_after_utc
				issued_date = x509_cert.not_valid_before_utc
				serial = x509_cert.serial_number
				issuer = x509_cert.issuer
				subject = x509_cert.subject
				# get labels
				labels = {
					"host": f"{host['name']}:{host['port']}",
					"issuer_C": self.get_oid_attribute(issuer, x509.oid.NameOID.COUNTRY_NAME),
					"issuer_L": self.get_oid_attribute(issuer, x509.oid.NameOID.LOCALITY_NAME),
					"issuer_O": self.get_oid_attribute(issuer, x509.oid.NameOID.ORGANIZATION_NAME),
					"issuer_OU": self.get_oid_attribute(issuer, x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME),
					"issuer_ST": self.get_oid_attribute(issuer, x509.oid.NameOID.STATE_OR_PROVINCE_NAME),
					"issuer_CN": self.get_oid_attribute(issuer, x509.oid.NameOID.COMMON_NAME),
					"serial_number": serial,
					"subject_C": self.get_oid_attribute(subject, x509.oid.NameOID.COUNTRY_NAME),
					"subject_L": self.get_oid_attribute(subject, x509.oid.NameOID.LOCALITY_NAME),
					"subject_O": self.get_oid_attribute(subject, x509.oid.NameOID.ORGANIZATION_NAME),
					"subject_OU": self.get_oid_attribute(subject, x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME),
					"subject_CN": self.get_oid_attribute(subject, x509.oid.NameOID.COMMON_NAME),
					"subject_ST": self.get_oid_attribute(subject, x509.oid.NameOID.STATE_OR_PROVINCE_NAME)
				}

				# add custom labels
				for label in self.config.labels:
					if label['name'] not in labels:
						labels[label['name']] = label['value']
				# set metrics
				self.not_valid_after.labels(**labels).set(expiration_date.timestamp())
				self.not_valid_before.labels(**labels).set(issued_date.timestamp())
				self.expired.labels(**labels).set(int(expiration_date < datetime.datetime.now(pytz.UTC)))
				self.host_read_errors.labels(host=f"{host['name']}:{host['port']}").set(0)
			except Exception as e:
				error_count += 1
				self.host_read_errors.labels(host=f"{host['name']}:{host['port']}").set(1)


		self.read_errors.set(error_count)
def dict_get(dictionary, key, default_value = None):
	if key in dictionary.keys():
		return dictionary[key] or default_value
	else:
		return default_value

def sighandler(signum, frame):
	print("<SIGTERM received>")
	exit(0)

def main():
	signal.signal(signal.SIGTERM, sighandler)

	try:
		config_file = dict_get(os.environ, "X509_CONFIG_FILE", default_value="./config/.configuration.yaml")

		config = AppConfig(config_file)

		print(f"start listening on :{config.metrics['port']}")
		app_metrics = X509Metrics(config)
		start_http_server(config.metrics['port'])
		app_metrics.run_metrics_loop()
	except KeyboardInterrupt:
		exit(0)

if __name__ == "__main__":
	main()
