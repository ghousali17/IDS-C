typedef struct src_host
{
	uint32_t src_ip;
	uint32_t data_sent;		   //TOTAL IP PAYLOAD
	double HH_ts;			   //TIME STAMP FOR HEAVY HITTER INTRUSION DETECTION
	struct des_host **targets; //LIST OF DESTINATION HOST [NEEDED FOR VERTICAL PORT SCAN DETECTION]
	struct src_host *next;
} src_host;

typedef struct ids_param
{
	uint32_t HH_threshold; // HEAVY HITTER THRESHOLD
	uint32_t HS_threshold; // HORINTAL PORT SCAN THRESHOLD
	uint32_t VS_threshold; // VERTICAL PORT SCAN THRESHOLD

} ids_param;

typedef struct des_host
{
	uint32_t des_ip;
	uint16_t port_count; //PORTS OF THE HOST MACHINE TARGETED BY A SPECIFIC IP
	double VS_ts;		 // TIME STAMP FOR VERTICAL PORT SCAN DETECTION
	struct des_host *next;
	struct des_port **port; //LIST OF PORTS OF THE SPECIFIC HOST TARGETED BY SPECIFIC SOURCE

} des_host;

typedef struct hs_port
{
	uint16_t port_number;
	struct hs_port *next;
	uint32_t host_count;
	struct hs_src **sources;
	//

} hs_port;

typedef struct hs_src
{
	uint32_t src_ip;
	struct hs_src *next;
	uint32_t des_count;
	struct hs_des **targets;
	double HS_ts;
} hs_src;

typedef struct hs_des
{
	uint32_t des_ip;
	struct hs_des *next;

} hs_des;

typedef struct des_port
{
	uint16_t port;
	struct des_port *next;
} des_port;