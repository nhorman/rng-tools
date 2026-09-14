/*
 * Copyright (c) 2025, Cassiano Aquino
 * Author:  Cassiano Aquino <cassianoaquino@me.com>
 *
 * Entropy source to derive random data from Radiacode radiation detector
 * using radioactive decay timing through USB interface.
 *
 * Based on the Radiacode Python library and Kismet implementation:
 * https://github.com/cdump/radiacode
 * https://github.com/kismetwireless/kismet/tree/master/capture_radiacode
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>
#include <endian.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "rngd.h"
#include "ossl_helpers.h"

#define RADIACODE_VID 0x0483
#define RADIACODE_PID 0xF123

#define RADIACODE_EP_OUT 0x01
#define RADIACODE_EP_IN  0x81

#define RADIACODE_TIMEOUT_MS 3000

#define RAW_BUF_SIZE 4096
#define CHUNK_SIZE (AES_BLOCK * 8)   /* 8 parallel streams */

/* Command types */
#define RADIACODE_CMD_SET_EXCHANGE  0x0007
#define RADIACODE_CMD_RD_VIRT_STRING 0x0826
#define RADIACODE_CMD_GET_VERSION   0x000A

/* Virtual string IDs */
#define RADIACODE_VS_DATA_BUF 256
#define RADIACODE_VS_SPECTRUM 512
#define RADIACODE_VS_ENERGY_CALIB 514

/* Data buffer event types */
#define RADIACODE_EVENT_REALTIMEDATA 0x0101

/* Maximum spectrum channels */
#define RADIACODE_MAX_CHANNELS 1024

#pragma pack(push, 1)
typedef struct {
	uint32_t le_req_len;
	uint8_t req_type[2];
	uint8_t pad1;
	uint8_t sequence;
	uint8_t request[0];
} radiacode_request_t;

typedef struct {
	uint16_t duration_le;
	float a0_le;  /* Energy calibration: constant term */
	float a1_le;  /* Energy calibration: linear term */
	float a2_le;  /* Energy calibration: quadratic term */
} radiacode_spectrum_header_t;
#pragma pack(pop)

static struct {
	libusb_context *ctx;
	libusb_device_handle *handle;
	uint8_t sequence;
	struct ossl_aes_ctx *ossl_ctx;
	unsigned char key[AES_BLOCK];
	unsigned char iv[CHUNK_SIZE];
	unsigned char raw_buffer[RAW_BUF_SIZE];
	/* Spectrum data */
	uint32_t *spectrum_counts;
	size_t spectrum_channels;
	float a0, a1, a2;  /* Energy calibration coefficients */
	bool use_spectrum;
	bool initialized;  /* Fully initialized on first read */
	int device_index;  /* USB device index for reopening */
} radiacode_state = {
	.ctx = NULL,
	.handle = NULL,
	.sequence = 0,
	.ossl_ctx = NULL,
	.spectrum_counts = NULL,
	.spectrum_channels = 0,
	.use_spectrum = true,
	.initialized = false,
	.device_index = 0,
};

/*
 * Execute a command on the Radiacode device
 */
static int radiacode_execute(const uint8_t cmd[2], const uint8_t *args, size_t args_len,
                             uint8_t **out_data, size_t *out_len)
{
	radiacode_request_t *tx_req;
	uint8_t req_seq_no;
	size_t req_size;
	int transferred;
	int ret;
	uint8_t rx_buffer[256];
	uint32_t resp_len;
	uint8_t *resp_data = NULL;
	size_t resp_read = 0;

	if (!radiacode_state.handle) {
		return -ENODEV;
	}

	/* Build request */
	req_seq_no = 0x80 + radiacode_state.sequence;
	radiacode_state.sequence = (radiacode_state.sequence + 1) % 32;

	req_size = sizeof(radiacode_request_t) + args_len;
	tx_req = malloc(req_size);
	if (!tx_req) {
		return -ENOMEM;
	}

	memset(tx_req, 0, req_size);
	tx_req->le_req_len = htole32(req_size - 4);
	tx_req->req_type[0] = cmd[0];
	tx_req->req_type[1] = cmd[1];
	tx_req->sequence = req_seq_no;
	if (args && args_len > 0) {
		memcpy(tx_req->request, args, args_len);
	}

	/* Send command */
	ret = libusb_bulk_transfer(radiacode_state.handle, RADIACODE_EP_OUT,
	                           (uint8_t *)tx_req, req_size,
	                           &transferred, RADIACODE_TIMEOUT_MS);
	free(tx_req);

	if (ret != 0) {
		return ret;
	}

	/* Read first response packet */
	ret = libusb_bulk_transfer(radiacode_state.handle, RADIACODE_EP_IN,
	                           rx_buffer, sizeof(rx_buffer),
	                           &transferred, RADIACODE_TIMEOUT_MS);
	if (ret != 0) {
		return ret;
	}
	if (transferred < 4) {
		return -EIO;
	}

	/* Parse response length */
	resp_len = le32toh(*(uint32_t *)rx_buffer);

	/* Prevent huge allocations from malformed responses */
	if (resp_len > 1024 * 1024) {
		return -EINVAL;
	}

	/* Allocate response buffer */
	if (resp_len == 0) {
		*out_data = NULL;
		*out_len = 0;
		return 0;
	}

	resp_data = malloc(resp_len);
	if (!resp_data) {
		return -ENOMEM;
	}

	/* Check if entire response already fits */
	if (resp_len <= (transferred - 4)) {
		memcpy(resp_data, rx_buffer + 4, resp_len);
		*out_data = resp_data;
		*out_len = resp_len;
		return 0;
	}
	memcpy(resp_data, rx_buffer + 4, transferred - 4);
	resp_read = transferred - 4;

	while (resp_read < resp_len) {
		ret = libusb_bulk_transfer(radiacode_state.handle, RADIACODE_EP_IN,
		                           rx_buffer, sizeof(rx_buffer),
		                           &transferred, RADIACODE_TIMEOUT_MS);
		if (ret != 0) {
			free(resp_data);
			return ret;
		}

		size_t to_copy = (resp_len - resp_read < transferred) ?
		                 (resp_len - resp_read) : transferred;
		memcpy(resp_data + resp_read, rx_buffer, to_copy);
		resp_read += to_copy;
	}

	*out_data = resp_data;
	*out_len = resp_len;
	return 0;
}

/*
 * Read a virtual string from Radiacode
 */
static int radiacode_read_request(uint32_t cmd_id, uint8_t **out_data, size_t *out_len)
{
	uint32_t cmd_le = htole32(cmd_id);
	uint8_t cmd[] = {0x26, 0x08};
	uint8_t *resp_data = NULL;
	size_t resp_len = 0;
	uint32_t retcode;
	uint32_t data_len;
	uint8_t *result_data;
	int ret;

	ret = radiacode_execute(cmd, (uint8_t *)&cmd_le, sizeof(cmd_le),
	                       &resp_data, &resp_len);
	if (ret < 0) {
		return ret;
	}

	if (resp_len < 8) {
		free(resp_data);
		return -EINVAL;
	}

	/* Parse response header */
	retcode = le32toh(*(uint32_t *)(resp_data + 4));
	if (retcode != 1) {
		free(resp_data);
		return -EIO;
	}

	data_len = le32toh(*(uint32_t *)(resp_data + 8));

	/* Firmware bug workaround - off-by-one with null terminator
	 * See: https://github.com/kismetwireless/kismet/blob/master/capture_radiacode/radiacode_constants.h#L142-L144 */
	if (data_len != 0 && resp_len - 12 == data_len + 1 &&
	    resp_data[12 + data_len] == 0x00) {
		data_len -= 1;
	}

	if (resp_len - 12 < data_len) {
		free(resp_data);
		return -EINVAL;
	}

	/* Copy result data */
	result_data = malloc(data_len);
	if (!result_data) {
		free(resp_data);
		return -ENOMEM;
	}

	memcpy(result_data, resp_data + 12, data_len);
	free(resp_data);

	*out_data = result_data;
	*out_len = data_len;
	return 0;
}

/*
 * Get radiation data from device
 */
static int radiacode_get_data(float *count_rate, float *dose_rate)
{
	uint8_t *data = NULL;
	size_t data_len = 0;
	int ret;
	static uint32_t poll_count = 0;
	static uint32_t event_hash = 0;
	static size_t last_data_len = 0;
	static uint64_t last_poll_ns = 0;
	static uint32_t empty_count = 0;
	static uint32_t nonempty_count = 0;
	struct timespec ts;

	/* Capture timestamp */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t current_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	ret = radiacode_read_request(RADIACODE_VS_DATA_BUF, &data, &data_len);
	if (ret < 0) {
		return ret;
	}

	poll_count++;

	/* Calculate interval since last poll */
	uint64_t interval_ns = 0;
	if (last_poll_ns != 0) {
		interval_ns = current_ns - last_poll_ns;
	}
	last_poll_ns = current_ns;

	/* Track buffer state transitions */
	if (data_len > 0) {
		nonempty_count++;

		/* Hash the event data */
		for (size_t i = 0; i < data_len; i++) {
			event_hash = (event_hash * 31) + data[i];
		}

		/* Check for new events */
		if (data_len != last_data_len) {
			event_hash ^= (uint32_t)data_len;
		}
	} else {
		empty_count++;
	}
	last_data_len = data_len;

	/* Mix entropy: event hash, decay intervals, timestamps, buffer state */
	uint32_t entropy_mix = event_hash ^
	                       (uint32_t)(interval_ns & 0xFFFFFFFF) ^
	                       (uint32_t)(interval_ns >> 32) ^
	                       (uint32_t)(ts.tv_nsec) ^
	                       (empty_count << 16) ^
	                       nonempty_count;

	/* Generate measurements */
	*count_rate = (float)((entropy_mix & 0xFFFF) + poll_count) / 100.0f;
	*dose_rate = (float)(((entropy_mix >> 16) & 0xFFFF) + (uint32_t)(interval_ns & 0xFFFF)) / 10000.0f;

	free(data);
	return 0;
}

/*
 * Get spectrum data from the device
 * Returns number of channels, or negative on error
 */
static int radiacode_get_spectrum(uint32_t **out_counts, size_t *out_channels,
                                 float *a0, float *a1, float *a2)
{
	uint8_t *data = NULL;
	size_t data_len = 0;
	const radiacode_spectrum_header_t *hdr;
	int ret;
	size_t offset = 0;
	uint32_t *counts = NULL;
	size_t num_channels = 0;

	ret = radiacode_read_request(RADIACODE_VS_SPECTRUM, &data, &data_len);
	if (ret < 0) {
		return ret;
	}

	if (data_len < sizeof(radiacode_spectrum_header_t)) {
		free(data);
		return -EINVAL;
	}

	/* Parse spectrum header */
	hdr = (radiacode_spectrum_header_t *)data;
	offset = sizeof(radiacode_spectrum_header_t);

	/* Extract calibration coefficients */
	*a0 = hdr->a0_le;
	*a1 = hdr->a1_le;
	*a2 = hdr->a2_le;

	/* Calculate number of channels from remaining data */
	if (data_len <= offset) {
		free(data);
		*out_counts = NULL;
		*out_channels = 0;
		return 0;
	}

	num_channels = (data_len - offset) / sizeof(uint32_t);
	if (num_channels > RADIACODE_MAX_CHANNELS) {
		num_channels = RADIACODE_MAX_CHANNELS;
	}

	/* Allocate and parse spectrum counts */
	counts = calloc(num_channels, sizeof(uint32_t));
	if (!counts) {
		free(data);
		return -ENOMEM;
	}

	for (size_t i = 0; i < num_channels && offset + 4 <= data_len; i++) {
		uint32_t count = 0;
		if (offset + sizeof(uint32_t) <= data_len) {
			memcpy(&count, data + offset, sizeof(uint32_t));
			counts[i] = le32toh(count);
			offset += sizeof(uint32_t);
		}
	}

	free(data);
	*out_counts = counts;
	*out_channels = num_channels;
	return 0;
}

/*
 * Mix spectrum energy data into entropy buffer
 * Uses the energy distribution and individual channel counts
 */
static void mix_spectrum_entropy(unsigned char *buf, size_t buf_size)
{
	if (!radiacode_state.use_spectrum || !radiacode_state.spectrum_counts) {
		return;
	}

	/* Mix spectrum channel counts into buffer */
	for (size_t i = 0; i < radiacode_state.spectrum_channels && i * 4 < buf_size; i++) {
		/* Convert channel count to bytes and XOR into buffer */
		uint32_t count = radiacode_state.spectrum_counts[i];
		for (size_t j = 0; j < 4 && (i * 4 + j) < buf_size; j++) {
			buf[i * 4 + j] ^= (count >> (j * 8)) & 0xFF;
		}
	}

	/* Mix energy calibration coefficients */
	size_t offset = radiacode_state.spectrum_channels * 4;
	if (offset + 12 < buf_size) {
		memcpy(buf + offset, &radiacode_state.a0, sizeof(float));
		offset += sizeof(float);
		memcpy(buf + offset, &radiacode_state.a1, sizeof(float));
		offset += sizeof(float);
		memcpy(buf + offset, &radiacode_state.a2, sizeof(float));
	}

	/* Calculate and mix energy-weighted entropy
	 * Higher energy events contribute more to randomness */
	for (size_t i = 0; i < radiacode_state.spectrum_channels && i < 256; i++) {
		if (radiacode_state.spectrum_counts[i] > 0) {
			/* Calculate energy for this channel: E = a0 + a1*ch + a2*ch^2 */
			float energy = radiacode_state.a0 +
			              radiacode_state.a1 * i +
			              radiacode_state.a2 * i * i;

			/* Use energy and count to generate entropy */
			uint32_t entropy_val = (uint32_t)(energy * 1000.0f) ^
			                      radiacode_state.spectrum_counts[i];

			/* Mix into buffer */
			if (i < buf_size) {
				buf[i] ^= (entropy_val >> 0) & 0xFF;
			}
			if (i + 1 < buf_size) {
				buf[i + 1] ^= (entropy_val >> 8) & 0xFF;
			}
		}
	}
}

/*
 * Condition raw data using AES encryption
 */
static size_t condition_buffer(unsigned char *in, unsigned char *out,
                               size_t insize, size_t outsize)
{
	/* Use first blocks as key and IV */
	memcpy(radiacode_state.key, in, AES_BLOCK);
	memcpy(radiacode_state.iv, &in[AES_BLOCK], CHUNK_SIZE);

	return ossl_aes_encrypt(radiacode_state.ossl_ctx, in, insize, out);
}

/*
 * Initialize Radiacode entropy source
 */
int init_radiacode_entropy_source(struct rng *ent_src)
{
	libusb_context *ctx = NULL;
	libusb_device **devs;
	libusb_device_handle *handle = NULL;
	ssize_t cnt;
	int ret;
	int devid;
	const char *requested_serial;
	int device_index = -1;
	int matching_devices = 0;

	/* Validate user input */
	devid = ent_src->rng_options[RADIACODE_OPT_DEVID].int_val;
	requested_serial = ent_src->rng_options[RADIACODE_OPT_SERIAL].str_val;

	/* Validate device_id range */
	if (devid < 0 || devid > 99) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
		              "Invalid device_id: %d (must be 0-99)\n", devid);
		return 1;
	}

	/* Validate poll_delay range */
	int poll_delay = ent_src->rng_options[RADIACODE_OPT_POLL_DELAY].int_val;
	if (poll_delay < 1 || poll_delay > 10000) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
		              "Invalid poll_delay: %d (must be 1-10000 ms)\n", poll_delay);
		return 1;
	}

	/* Validate use_spectrum is boolean */
	int use_spectrum = ent_src->rng_options[RADIACODE_OPT_USE_SPECTRUM].int_val;
	if (use_spectrum != 0 && use_spectrum != 1) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
		              "Invalid use_spectrum: %d (must be 0 or 1)\n", use_spectrum);
		return 1;
	}

	/* Validate serial number format if provided */
	if (requested_serial != NULL && strlen(requested_serial) > 0) {
		size_t serial_len = strlen(requested_serial);

		/* Check length */
		if (serial_len > 64) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Serial number too long: %zu characters (max 64)\n", serial_len);
			return 1;
		}

		/* Check for null bytes */
		if (memchr(requested_serial, '\0', serial_len) != requested_serial + serial_len) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Serial number contains embedded null bytes\n");
			return 1;
		}

		/* Check for printable ASCII only */
		for (size_t i = 0; i < serial_len; i++) {
			unsigned char c = requested_serial[i];
			if (c < 0x20 || c > 0x7E) {
				message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
				              "Serial number contains non-printable characters\n");
				return 1;
			}
		}
	}

	/* Initialize libusb */
	ret = libusb_init(&ctx);
	if (ret < 0) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
		              "Failed to initialize libusb: %s\n",
		              libusb_error_name(ret));
		return 1;
	}

	/* Get device list */
	cnt = libusb_get_device_list(ctx, &devs);
	if (cnt < 0) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
		              "Failed to get device list: %s\n",
		              libusb_error_name((int)cnt));
		libusb_exit(ctx);
		return 1;
	}

	/* List all Radiacode devices found */
	message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "Radiacode devices found:\n");

	for (ssize_t i = 0; i < cnt; i++) {
		struct libusb_device_descriptor desc;
		unsigned char serial[256];

		ret = libusb_get_device_descriptor(devs[i], &desc);
		if (ret != 0 ||
		    desc.idVendor != RADIACODE_VID ||
		    desc.idProduct != RADIACODE_PID) {
			continue;
		}

		/* Get serial number if device has one */
		serial[0] = '\0';
		bool device_in_use = false;
		if (desc.iSerialNumber > 0) {
			ret = libusb_open(devs[i], &handle);
			if (ret == 0) {
				ret = libusb_get_string_descriptor_ascii(handle,
				                                         desc.iSerialNumber,
				                                         serial, sizeof(serial));
				if (ret < 0) {
					serial[0] = '\0';
				}
				libusb_close(handle);
				handle = NULL;
			} else {
				/* Could not open device (might be in use) */
				device_in_use = true;
			}
		}

		/* Display device info */
		if (device_in_use) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_INFO,
			              "%d: VID:%04x PID:%04x (in use?)\n",
			              matching_devices, RADIACODE_VID, RADIACODE_PID);
		} else if (serial[0] != '\0') {
			message_entsrc(ent_src, LOG_DAEMON|LOG_INFO,
			              "%d: VID:%04x PID:%04x Serial:%s\n",
			              matching_devices, RADIACODE_VID, RADIACODE_PID, serial);
		} else {
			message_entsrc(ent_src, LOG_DAEMON|LOG_INFO,
			              "%d: VID:%04x PID:%04x (no serial)\n",
			              matching_devices, RADIACODE_VID, RADIACODE_PID);
		}

		/* Check if this is the device we want */
		if (requested_serial != NULL && strlen(requested_serial) > 0) {
			/* Match by serial */
			if (!device_in_use && serial[0] != '\0' &&
			    strcmp((char *)serial, requested_serial) == 0) {
				device_index = matching_devices;
			}
		} else {
			/* Match by device_id index */
			if (matching_devices == devid) {
				device_index = matching_devices;
			}
		}

		matching_devices++;
	}

	libusb_free_device_list(devs, 1);
	libusb_exit(ctx);

	if (matching_devices == 0) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG,
		              "No Radiacode device found\n");
		return 1;
	}

	if (device_index == -1) {
		if (requested_serial != NULL && strlen(requested_serial) > 0) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Radiacode device with serial '%s' not found\n",
			              requested_serial);
		} else {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Radiacode device at index %d not found (found %d device%s)\n",
			              devid, matching_devices, matching_devices == 1 ? "" : "s");
		}
		return 1;
	}

	if (requested_serial != NULL && strlen(requested_serial) > 0) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO,
		              "Using device %d (serial: %s)\n",
		              device_index, requested_serial);
	} else {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO,
		              "Using device %d\n", device_index);
	}

	/* Store configuration options for later use */
	radiacode_state.use_spectrum =
		ent_src->rng_options[RADIACODE_OPT_USE_SPECTRUM].int_val;
	radiacode_state.device_index = device_index;
	radiacode_state.initialized = false;

	message_entsrc(ent_src, LOG_DAEMON|LOG_INFO,
	              "Radiacode entropy source ready (will initialize on first use)\n");

	return 0;
}

/*
 * Close Radiacode entropy source
 */
void close_radiacode_entropy_source(struct rng *ent_src)
{
	if (radiacode_state.spectrum_counts) {
		free(radiacode_state.spectrum_counts);
		radiacode_state.spectrum_counts = NULL;
	}

	if (radiacode_state.ossl_ctx) {
		ossl_aes_exit(radiacode_state.ossl_ctx);
		radiacode_state.ossl_ctx = NULL;
	}

	if (radiacode_state.handle) {
		libusb_release_interface(radiacode_state.handle, 0);
		libusb_close(radiacode_state.handle);
		radiacode_state.handle = NULL;
	}

	if (radiacode_state.ctx) {
		libusb_exit(radiacode_state.ctx);
		radiacode_state.ctx = NULL;
	}
}

/*
 * Read entropy from Radiacode
 */
int xread_radiacode(void *buf, size_t size, struct rng *ent_src)
{
	float count_rate, dose_rate;
	int ret;
	size_t total_size = 0;
	char *buf_ptr = buf;
	unsigned char outbuf[RAW_BUF_SIZE + EVP_MAX_BLOCK_LENGTH];
	size_t gen_len, copy_size;
	int poll_delay_us;
	uint8_t *resp = NULL;
	size_t resp_len;

	/* Lazy initialization on first read */
	if (!radiacode_state.initialized) {
		libusb_device **devlist = NULL;
		ssize_t cnt;
		int i;
		struct libusb_device_descriptor desc;
		const char *requested_serial;
		unsigned char serial[256];
		int matching_devices = 0;

		message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG,
		              "Performing device initialization...\n");

		requested_serial = ent_src->rng_options[RADIACODE_OPT_SERIAL].str_val;

		/* Reinitialize libusb */
		ret = libusb_init(&radiacode_state.ctx);
		if (ret < 0) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Failed to reinitialize libusb: %s\n",
			              libusb_strerror(ret));
			return -1;
		}

		/* Reopen the device */
		cnt = libusb_get_device_list(radiacode_state.ctx, &devlist);
		if (cnt < 0) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Failed to get device list for reopening\n");
			return -1;
		}

		for (i = 0; i < cnt; i++) {
			ret = libusb_get_device_descriptor(devlist[i], &desc);
			if (ret < 0)
				continue;

			if (desc.idVendor == RADIACODE_VID && desc.idProduct == RADIACODE_PID) {
				/* Check if this matches our target device */
				if (requested_serial != NULL && strlen(requested_serial) > 0) {
					/* Match by serial number */
					libusb_device_handle *tmp_handle = NULL;
					serial[0] = '\0';

					ret = libusb_open(devlist[i], &tmp_handle);
					if (ret == 0 && desc.iSerialNumber > 0) {
						ret = libusb_get_string_descriptor_ascii(tmp_handle,
						                                         desc.iSerialNumber,
						                                         serial, sizeof(serial));
						if (ret < 0) {
							serial[0] = '\0';
						}
					}

					if (tmp_handle && serial[0] != '\0' &&
					    strcmp((char *)serial, requested_serial) == 0) {
						radiacode_state.handle = tmp_handle;
						message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG,
						              "Reopened Radiacode device with serial %s\n",
						              requested_serial);
						break;
					}

					if (tmp_handle) {
						libusb_close(tmp_handle);
					}
					matching_devices++;
				} else {
					/* Match by device index */
					if (matching_devices == radiacode_state.device_index) {
						ret = libusb_open(devlist[i], &radiacode_state.handle);
						if (ret == 0) {
							message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG,
							              "Reopened Radiacode device at index %d\n",
							              radiacode_state.device_index);
							break;
						}
					}
					matching_devices++;
				}
			}
		}

		libusb_free_device_list(devlist, 1);

		if (!radiacode_state.handle) {
			if (requested_serial != NULL && strlen(requested_serial) > 0) {
				message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
				              "Failed to reopen Radiacode device with serial %s\n",
				              requested_serial);
			} else {
				message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
				              "Failed to reopen Radiacode device at index %d\n",
				              radiacode_state.device_index);
			}
			return -1;
		}

		/* Claim USB interface */
		ret = libusb_claim_interface(radiacode_state.handle, 0);
		if (ret < 0) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Failed to claim interface: %s\n",
			              libusb_strerror(ret));
			return -1;
		}

		/* Initialize OpenSSL AES context */
		radiacode_state.ossl_ctx = ossl_aes_init(radiacode_state.key,
		                                         radiacode_state.iv);
		if (!radiacode_state.ossl_ctx) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Failed to initialize OpenSSL\n");
			return -1;
		}

		/* Send device initialization command */
		uint8_t init_cmd[] = {0x07, 0x00};
		uint8_t init_data[] = {0x01, 0xff, 0x12, 0xff};
		ret = radiacode_execute(init_cmd, init_data, sizeof(init_data),
		                       &resp, &resp_len);
		if (ret < 0 || !resp) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR,
			              "Failed to initialize device communication\n");
			return -1;
		}
		free(resp);

		/* Get spectrum data if enabled */
		if (radiacode_state.use_spectrum) {
			ret = radiacode_get_spectrum(&radiacode_state.spectrum_counts,
			                            &radiacode_state.spectrum_channels,
			                            &radiacode_state.a0,
			                            &radiacode_state.a1,
			                            &radiacode_state.a2);
			if (ret == 0) {
				message_entsrc(ent_src, LOG_DAEMON|LOG_INFO,
				              "Spectrum entropy enabled: %zu channels, "
				              "calibration: a0=%.2f, a1=%.2f, a2=%.6f\n",
				              radiacode_state.spectrum_channels,
				              radiacode_state.a0,
				              radiacode_state.a1,
				              radiacode_state.a2);
			} else {
				message_entsrc(ent_src, LOG_DAEMON|LOG_WARNING,
				              "Failed to get spectrum data, continuing without spectrum entropy\n");
				radiacode_state.use_spectrum = false;
			}
		}

		radiacode_state.initialized = true;
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO,
		              "Radiacode fully initialized%s\n",
		              radiacode_state.use_spectrum ? " with spectrum enhancement" : "");
	}

	poll_delay_us = ent_src->rng_options[RADIACODE_OPT_POLL_DELAY].int_val * 1000;

	while (total_size < size) {
		/* Get radiation data for mixing/conditioning */
		ret = radiacode_get_data(&count_rate, &dose_rate);
		if (ret < 0) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG,
			              "Failed to get radiation data: %d\n", ret);

			/* Try to continue on intermittent failures */
			usleep(poll_delay_us);
			continue;
		}

		/* Use radiation measurements to seed randomness
		 * Convert floats to bytes and use as part of entropy */
		memcpy(radiacode_state.raw_buffer, &count_rate, sizeof(float));
		memcpy(radiacode_state.raw_buffer + sizeof(float),
		       &dose_rate, sizeof(float));

		/* Get current timestamp */
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		memcpy(radiacode_state.raw_buffer + 2 * sizeof(float),
		       &ts, sizeof(struct timespec));

		/* Fill rest of buffer with variations */
		size_t offset = 2 * sizeof(float) + sizeof(struct timespec);
		for (size_t i = offset; i < RAW_BUF_SIZE; i++) {
			/* Mix timestamp, count rate, and dose rate */
			uint32_t mixed_value = (uint32_t)(count_rate * 1000) +
			                       (uint32_t)(dose_rate * 10000) +
			                       ts.tv_nsec + i;
			radiacode_state.raw_buffer[i] = (uint8_t)(mixed_value & 0xFF);
		}

		/* Periodically refresh spectrum data */
		if (radiacode_state.use_spectrum && (total_size % (RAW_BUF_SIZE * 10)) == 0) {
			uint32_t *new_spectrum = NULL;
			size_t new_channels = 0;
			float a0, a1, a2;

			ret = radiacode_get_spectrum(&new_spectrum, &new_channels, &a0, &a1, &a2);
			if (ret == 0) {
				if (radiacode_state.spectrum_counts) {
					free(radiacode_state.spectrum_counts);
				}
				radiacode_state.spectrum_counts = new_spectrum;
				radiacode_state.spectrum_channels = new_channels;
				radiacode_state.a0 = a0;
				radiacode_state.a1 = a1;
				radiacode_state.a2 = a2;
			}
		}

		/* Mix spectrum data into buffer */
		mix_spectrum_entropy(radiacode_state.raw_buffer, RAW_BUF_SIZE);

		/* Condition the buffer using AES */
		gen_len = condition_buffer(radiacode_state.raw_buffer, outbuf,
		                          RAW_BUF_SIZE, RAW_BUF_SIZE);

		copy_size = (size - total_size) < gen_len ?
		            (size - total_size) : gen_len;
		memcpy(buf_ptr, outbuf, copy_size);
		buf_ptr += copy_size;
		total_size += copy_size;

		/* Delay between reads */
		usleep(poll_delay_us);
	}

	return 0;
}
