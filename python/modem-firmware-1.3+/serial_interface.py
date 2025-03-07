from abc import ABC, abstractmethod
from cli_helpers import error_style, send_style
import cli_helpers
import time
import sys
import rtt_interface
import re

class SerialInterface(ABC):
	default_prompt = None

	def set_default_prompt(self, prompt):
		self.default_prompt = prompt

	def wait_for_prompt(self, prompt, timeout=15):
		""" Wait for a prompt to be shown """
		if prompt is None:
			prompt = self.default_prompt

		if prompt is None:
			return False

		return self.wait_for_success_or_fail(prompt, None, timeout)

	def wait_for_success_or_fail(self, success, fail=None, timeout=15, capture=None):
		""" Wait for success or failure string.

		Wait for one of two specified inputs representing either success or failure,
		for up to the specified timeout, optionally capturing a single response line.

		Args:
			success: The string representing success.
			fail: The string representing failure.
			timeout: Timeout (seconds) to wait for success or failure
			capture: The final line containing this string will be returned

		Returns:
			status: True if success condition seen, otherwise False
			output: If capture was provided, the last-seen line matching it.
		"""
		deadline = time.time() + timeout
		conditions = [success] if fail is None else [success, fail]
		index, outputs = self.wait_for_pattern([success, fail], [capture], False, timeout)

		status = index == 0
		output = outputs[-1] if len(outputs) > 0 else None

		if capture != None and output == None:
			print(error_style('String {} not detected in line {}'.format(store, line)))

		if time.time() > deadline:
			print(error_style('Serial timeout'))

		return index, output

	def wait_for_pattern(self, stop_patterns, capture_patterns, regex=False, timeout=15):
		""" Wait for any of a list of patterns to be matched.

		Wait for a line to be printed which matches any of the provided patterns.
		The index of the matching pattern is returned.

		If capture_patterns is provided, all lines matching at least one of the provided
		patterns will be collected and returned as a list of matching lines.

		stop_patterns and capture_patterns can each be either an array of patterns,
		or a single pattern.

		Patterns can be either simple strings, or treated as regexes.

		Args:
			stop_patterns: A single pattern, or list of patterns. Waiting/capture stop
				       if any of these patterns matches a line.
			capture_patterns: A single pattern, or list of patterns, or None. If not
					  None, any lines which match any of these patterns will be
					  captured.
			regex: A boolean. True if patterns should be treated as Regexes. False if
			       they should be treated as simple strings.
			timeout: Timeout (seconds) to wait for a stop_pattern match.

		Returns:
			index: The index of the stop_pattern that was matched. -1 if timeout.
			outputs: All captured lines, in order of appearance.
		"""

		# Sanitize pattern inputs
		if stop_patterns is None:
			raise RuntimeError("stop_patterns cannot be None")
		elif not isinstance(stop_patterns, list):
			stop_patterns = [stop_patterns]

		if (not isinstance(capture_patterns, list)) and (capture_patterns is not None):
			capture_patterns = [capture_patterns]

		self.flush()

		# Collect lines until conditions are met
		output = []
		deadline = time.time() + timeout
		idx = -1

		while (idx == -1) and (time.time() < deadline):
			line = self.read_line(deadline - time.time())

			if line is None:
				continue

			if (capture_patterns is not None):
				if _matches_patterns(line, capture_patterns, regex) != -1:
					output.append(line)

			idx = _matches_patterns(line, stop_patterns, regex)

		self.flush()

		return idx, output

	@abstractmethod
	def write_line(self, line, hidden=True):
		"""Write a line to the serial interface."""
		return

	@abstractmethod
	def read_line(self, timeout):
		"""Read a single line from the serial interface."""
		return

	@abstractmethod
	def flush(self):
		"""Clear any pending lins of data"""
		return

	def notify_line(self, line, read):
		"""Implementers must call this when (non-hidden) lines are read or written"""
		if read:
			sys.stdout.write('<- ' + line)
			if '\n' not in line:
        			sys.stdout.write('\n')
		else:
			print(send_style('-> ' + line))


def _matches_patterns(line, patterns, regex):
	"""Check if a line matches any of the provided string or regex patterns"""
	for idx, pattern in enumerate(patterns):
		if _matches_pattern(line, pattern, regex):
			return idx
	return -1

def _matches_pattern(line, pattern, regex):
	if regex:
		return bool(re.search(pattern, line))
	else:
		return str(pattern) in str(line)


# TODO: Split this implementation into two separate RTT and UART implementations?
class SerialInterfaceGeneric(SerialInterface):
	terminator = '\n'

	def __init__(self, ser, rtt):
		self.ser = ser
		self.rtt = rtt

	def write_line(self, line, hidden=False):
		if not hidden:
			self.notify_line(line, False)

		line += self.terminator

		if self.ser:
			self.ser.write(bytes((line).encode('utf-8')))
		elif self.rtt:
			rtt_interface.send_rtt(self.rtt, line)

	def flush(self):
		print("Does flushing occur?");
		if self.ser:
			self.ser.flush()
		else:
			# TODO: Actually flush the RTT low-level API instead of just clearing the
			# tail.
			rtt_interface.clear_rtt_tail(self.rtt)

	def read_line(self, timeout):
		line = None
		deadline = time.time() + timeout
		while (line is None) and (time.time() < deadline):
			if self.ser:
				line = str(self.ser.readline(), encoding=cli_helpers.full_encoding)
			else:
				line = rtt_interface.readline_rtt(rtt, deadline - time.time())

			if line == b'\r\n':
				# Skip the initial CRLF (see 3GPP TS 27.007 AT cmd specification)
				line = None

			if line is not None:
				self.notify_line(line, True)

		return line

	def set_terminator(self, terminator):
		self.terminator = terminator
