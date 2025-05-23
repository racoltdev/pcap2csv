import pyshark
import csv
import argparse
from collections  import OrderedDict
import os
import sys
import time

def progress_bar(completed, total, start_time, bar_length=40):
	progress = int((completed / total) * bar_length)
	done = "█" * progress
	not_done = "-" * (bar_length - progress)
	bar = done + not_done

	percent = f"{((completed / total) * 100):.2f}%"

	current_time = int(time.time())
	elapsed_time = current_time - start_time
	format_elapsed = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

	estimated_end_time = 0;
	# Catch divide by zero errors
	if (completed != 0):
		estimated_end_time = int(elapsed_time * (total / completed))
	estimated_end_format =  time.strftime("%H:%M:%S", time.gmtime(estimated_end_time))

	sys.stdout.write(f"\r\t{percent} [{bar}] | {format_elapsed}<{estimated_end_format}")
	sys.stdout.flush()

def pcap_to_csv(input_file, output_file):
	file_size = os.path.getsize(input_file)
	total_packets = 0

	# keep_packets unloads a packet once it has been generated
	# preserves memory for large cap files
	# include_raw would be used to determine scan process, but it requires use_json, which creates strange fields names, or use_ek, which is broken
	capture = pyshark.FileCapture(input_file, keep_packets=False)

	master_fields = set()

	scanned_running_sum = 0

	start_time = int(time.time())
	print("Scanning all packets to initialize fields")
	print("Field initialization progress estimate:")
	progress_bar(scanned_running_sum, file_size, start_time)
	for packet_number, packet in enumerate(capture, start=1):
		fields = []

		for layer in packet:
			for field_name in layer.field_names:
				try:
					field = f"{layer.layer_name}.{field_name}"
					fields.append(field)
				except AttributeError:
					# Skip fields that can't be accessed
					pass

		# This is as close as I can get without breaking things or reading duplicates
		scanned_running_sum += int(packet.length) * 1.2
		total_packets += 1
		master_fields.update(fields)

		if packet_number % 5000 == 0:
			progress_bar(scanned_running_sum, file_size, start_time)

	print()
	print("First pass completed. All fields initialized")
	print("Writing packet data to csv")
	field_names = sorted(master_fields)

	with open(output_file, 'w', newline='') as csvfile:
		writer = csv.DictWriter(csvfile, fieldnames=field_names)
		writer.writeheader()

		start_time = int(time.time())
		print("CSV writing progress estimate: ")
		progress_bar(0, total_packets, start_time)

		for packet_number, packet in enumerate(capture, start=1):
			# Fill in missing fields with empty strings
			row = {}
			for field in field_names:
				layer = field.split(".")[0]
				f = ".".join(field.split(".")[1:])
				val = ''
				if layer in packet:
					layer = getattr(packet, layer)
					if hasattr(layer, f):
						val = getattr(layer, f)
				row[field] = val
			writer.writerow(row)

			if packet_number % 500 == 0:
				progress_bar(packet_number, total_packets, start_time)

	print()
	print(f"Conversion complete. Output saved to {output_file}")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Convert PCAP to CSV")
	parser.add_argument("input", help="Input PCAP file")
	parser.add_argument("output", help="Output CSV file")
	args = parser.parse_args()

	pcap_to_csv(args.input, args.output)

