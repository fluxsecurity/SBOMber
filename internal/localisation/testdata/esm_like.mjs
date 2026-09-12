const isDomainOrSubdomain = (destination, original) => {
	return destination === original;
};

export default async function fetch(url, options_) {
	if (!isDomainOrSubdomain(url, options_.origin)) {
		throw new Error('blocked');
	}
	return url;
}

function helper() {
	return 1;
}

export { helper as publicHelper };
export class Headers {
	get(name) {
		return name;
	}
}
